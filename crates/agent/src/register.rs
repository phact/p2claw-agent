//! Registration flow: `POST <coord>/v1/register` with a signed
//! proof. Translates the coordination
//! response into an [`AgentState`] the agent can persist.
//!
//! The signed payload is built by `p2claw_identity::sign_registration`
//! (domain separator `p2claw-register-v1`) — this module only deals
//! with the on-the-wire HTTP envelope.
//!
//! # Retry policy
//!
//! For long-lived run-mode use [`register_with_retry`]: it loops
//! [`register`] with exponential backoff (1s base, 60s cap, ±20%
//! jitter — same curve as the control connection's reconnect), and
//! distinguishes transient failures (network errors, 5xx, 429 honoring
//! a `retry_after` field) from
//! permanent ones (410 `revoked`, 400 `invalid_signature`,
//! 400 `pubkey_bad_length`, 500 `alias_exhausted`) where retrying
//! cannot help. Permanent failures bubble out as
//! [`RegisterError::Permanent`] so the caller can exit non-zero.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p2claw_identity::SigningKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;

use crate::state_store::AgentState;
use p2claw_identity::PeerId;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("system clock is before the unix epoch: {0}")]
    Clock(String),
    #[error("identity error: {0}")]
    Identity(#[from] p2claw_identity::IdentityError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordination returned {status}: {body}")]
    Coord { status: u16, body: String },
    /// Coordination returned a status that retrying cannot fix
    /// (`410 revoked`, `400 invalid_signature`, …). Operator must
    /// intervene; the run loop exits non-zero.
    #[error("coordination returned permanent {status} ({error}): {body}")]
    Permanent {
        status: u16,
        error: String,
        body: String,
    },
    /// The retry loop was cancelled by the shutdown signal.
    #[error("registration cancelled by shutdown")]
    Cancelled,
}

/// Exact JSON shape of the request body.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub pubkey_b64url: String,
    pub timestamp: u64,
    pub signature_b64url: String,
}

/// Exact JSON shape of the response body.
///
/// `peer_id` and `control_url` are carried through for tracing /
/// future cross-checks but the agent doesn't need them on the happy
/// path: `peer_id` is already known (it's our pubkey) and
/// `control_url` is derived from `coord_domain`.
///
/// Serde does **not** set `deny_unknown_fields` on this struct, so
/// future coord-side additions (`alias_kind`, `binding_sig_b64url`,
/// `binding_issued_at`, etc.) are
/// silently ignored. The agent doesn't need them; the bootstrap and
/// edge are the consumers of the binding fields.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RegisterResponse {
    pub peer_id: String,
    pub alias: String,
    pub parent_domain: String,
    pub control_url: String,
    /// Legacy bearer token field. Iroh QUIC's TLS handshake
    /// authenticates the dialer's `peer_id` via the cert binding,
    /// so a separate bearer is redundant. Kept for serde compat
    /// until coord drops the field from the wire; agent-side never
    /// reads it.
    pub control_token: String,
    pub coord_domain: String,
    /// Coord's root pubkey, base64url-no-pad-encoded (32 bytes
    /// decoded). Same key the bootstrap pins for binding-sig
    /// verification. Used as the Iroh `NodeID` the agent dials for
    /// the control plane. Persisted in `AgentState` and stable
    /// forever (coord-key rotation is not supported).
    pub coord_root_pubkey_b64url: String,
    /// Coord's iroh relay URL, if it advertises one. Same format
    /// as `/v1/connect`'s `iroh_relay_url`. `Option<String>`
    /// because production coord typically rides on a public relay
    /// and self-hosted setups may have none. **Optional in the
    /// response shape**: `#[serde(default)]` so older coord
    /// builds that don't emit this field decode cleanly with
    /// `None`; agents whose `agent.state` lacks it re-register on
    /// next start (the value is part of the dialed addressing —
    /// without it the agent can't dial under hermetic mode anyway).
    #[serde(default)]
    pub iroh_relay_url: Option<String>,
    /// Coord's iroh direct addresses (publicly reachable
    /// `ip:port` pairs). Same shape as `/v1/connect`'s
    /// `iroh_direct_addrs`. Required for hermetic dial
    /// (relay-disabled): without addrs, Iroh's discovery has no
    /// way to find coord. Empty Vec on older coord builds.
    #[serde(default)]
    pub iroh_direct_addrs: Vec<String>,
}

/// Body shape for coord error responses we want to inspect — we read
/// the `error` code and `retry_after` (seconds) when present. Both
/// fields are optional so plain-text error bodies don't trip parsing.
#[derive(Debug, Deserialize)]
struct CoordErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    retry_after: Option<u64>,
}

impl From<RegisterResponse> for AgentState {
    fn from(r: RegisterResponse) -> Self {
        // Decode coord's root pubkey at the parsing boundary so the
        // dial site never repeats the base64 step. A malformed
        // pubkey here would be a coord-side bug; we surface it as
        // an all-zeros sentinel + a `warn!` so the agent boots and
        // the dial site refuses, rather than crashing on a bad
        // response. Stable in practice — coord's response is
        // pinned by the integration tests on coord side.
        let coord_root_pubkey = decode_coord_root_pubkey(&r.coord_root_pubkey_b64url)
            .unwrap_or_else(|e| {
                warn!(
                    error = %e,
                    raw = %r.coord_root_pubkey_b64url,
                    "register: coord_root_pubkey_b64url decode failed; \
                     persisting zero sentinel — coord-side bug"
                );
                PeerId::from_bytes([0u8; 32])
            });
        AgentState {
            alias: r.alias,
            coord_domain: r.coord_domain,
            parent_domain: r.parent_domain,
            coord_root_pubkey,
            coord_iroh_relay_url: r.iroh_relay_url,
            coord_iroh_direct_addrs: r.iroh_direct_addrs,
        }
    }
}

fn decode_coord_root_pubkey(b64: &str) -> Result<PeerId, String> {
    let raw = B64_URL.decode(b64).map_err(|e| format!("base64: {e}"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", raw.len()))?;
    Ok(PeerId::from_bytes(bytes))
}

/// Build a signed registration request. Pure — exposed for tests and
/// for callers that want to stage the timestamp themselves.
pub fn build_request(
    sk: &SigningKey,
    coord_domain: &str,
    timestamp: u64,
) -> Result<RegisterRequest, RegisterError> {
    let pubkey = sk.peer_id();
    let sig = p2claw_identity::sign_registration(sk, coord_domain, timestamp)?;
    Ok(RegisterRequest {
        pubkey_b64url: URL_SAFE_NO_PAD.encode(pubkey.as_bytes()),
        timestamp,
        signature_b64url: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    })
}

/// Perform the full registration round-trip against `coord_url`
/// (expected to be the scheme+host prefix, e.g. `https://coord.p2claw.com`).
/// `coord_domain` MUST equal the FQDN coordination expects to see in
/// the signed payload — usually the host part of `coord_url`.
pub async fn register(
    coord_url: &str,
    coord_domain: &str,
    sk: &SigningKey,
) -> Result<RegisterResponse, RegisterError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| RegisterError::Clock(e.to_string()))?
        .as_secs();
    let req = build_request(sk, coord_domain, ts)?;

    let endpoint = format!("{}/v1/register", coord_url.trim_end_matches('/'));
    info!(endpoint = %endpoint, "POST /v1/register");

    let client = reqwest::Client::builder()
        .user_agent(concat!("p2claw/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let resp = client.post(&endpoint).json(&req).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(RegisterError::Coord {
            status: status.as_u16(),
            body,
        });
    }
    let body: RegisterResponse = resp.json().await?;
    Ok(body)
}

/// Wire shape of `GET /v1/coord-self`. Pure transport
/// refresh — no token rotation, no DB writes, no proof. The agent
/// calls this on N consecutive Iroh dial timeouts, persists the
/// result into `agent.state` (`coord_iroh_direct_addrs` +
/// `coord_iroh_relay_url` + maybe `coord_root_pubkey` if rotation
/// ever ships), and retries the dial.
///
/// `endpoint_id` is z-base-32 here, NOT base64url-no-pad like
/// `RegisterResponse.coord_root_pubkey_b64url`; the endpoint uses
/// the Iroh-native encoding. Caller decodes via `EndpointId::from_str`.
#[derive(Debug, Deserialize)]
pub struct CoordSelfResponse {
    /// Coord's iroh `EndpointId` in z-base-32. Stable across coord
    /// restarts (derived from coord's root signing key, which is
    /// preserved across restarts per the deploy posture).
    pub endpoint_id: String,
    /// Bare `host:port` direct UDP addresses. Empty if the
    /// listener hasn't published anything yet (cold start, watcher
    /// hasn't ticked) — caller decides whether to retry or fall
    /// back to register.
    #[serde(default)]
    pub direct_addrs: Vec<String>,
    /// Relay URL coord publishes when running with relay enabled.
    /// `None` for direct-only deployments (the production default).
    #[serde(default)]
    pub relay_url: Option<String>,
}

#[derive(Debug, Error)]
pub enum CoordSelfError {
    #[error("coord-self http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coord-self http {status}: {body}")]
    Coord { status: u16, body: String },
}

/// `GET /v1/coord-self` — fetch coord's current Iroh transport
/// coordinates without going through `/v1/register` (which has the
/// side effect of rotating the agent's `control_token`).
///
/// Used by the stranded-agent recovery path in `coord_conn` — see
/// the dial-timeout-counter logic + the persistence step that
/// writes the response into `agent.state`. Pure HTTP fetch; no
/// proof signature, no body. The endpoint's authn model is the
/// same as `/v1/register`: TLS to coord's HTTPS port, trusted by
/// virtue of the bootstrap-bundled root pubkey pinning.
pub async fn fetch_coord_self(coord_url: &str) -> Result<CoordSelfResponse, CoordSelfError> {
    let endpoint = format!("{}/v1/coord-self", coord_url.trim_end_matches('/'));
    info!(endpoint = %endpoint, "GET /v1/coord-self");

    let client = reqwest::Client::builder()
        .user_agent(concat!("p2claw/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let resp = client.get(&endpoint).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(CoordSelfError::Coord {
            status: status.as_u16(),
            body,
        });
    }
    let body: CoordSelfResponse = resp.json().await?;
    Ok(body)
}

/// Retry policy for [`register_with_retry`]. Curve mirrors the control
/// connection's reconnect: same
/// expectation that operators see consistent timing across the two
/// loops a long-running agent depends on.
#[derive(Debug, Clone, Copy)]
pub struct RegisterRetryPolicy {
    pub base: Duration,
    pub cap: Duration,
    /// Each attempt's wait is multiplied by this factor.
    pub multiplier: u32,
}

impl Default for RegisterRetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            multiplier: 2,
        }
    }
}

/// Outcome classification for a single registration attempt.
#[derive(Debug)]
enum Disposition {
    Done(Box<RegisterResponse>),
    /// Backoff + retry. `hint` is the server-suggested wait in seconds
    /// (parsed from `retry_after` on 429).
    Transient {
        reason: String,
        hint: Option<u64>,
    },
    Permanent {
        status: u16,
        error: String,
        body: String,
    },
}

/// Loop [`register`] with exponential backoff + jitter until coord
/// returns success, the failure becomes permanent, or `shutdown` is
/// signalled. Honors the `retry_after` field on `429 rate_limited`
/// (as the next wait floor — never more than the cap).
///
/// Permanent statuses:
///
/// - `410 revoked` — operator must un-revoke at coord.
/// - `400 invalid_signature`, `400 pubkey_bad_length` — identity is
///   broken; either the on-disk key is corrupt or the request was
///   malformed. Retrying won't fix it.
/// - `500 alias_exhausted` — coord ran out of aliases at every
///   prefix length. Retrying just thrashes coord; surface to ops.
pub async fn register_with_retry(
    coord_url: &str,
    coord_domain: &str,
    sk: &SigningKey,
    policy: RegisterRetryPolicy,
    mut shutdown: watch::Receiver<bool>,
) -> Result<RegisterResponse, RegisterError> {
    let mut wait = policy.base;
    let mut attempt: u32 = 0;
    loop {
        if *shutdown.borrow() {
            return Err(RegisterError::Cancelled);
        }
        attempt += 1;
        let disp = attempt_register(coord_url, coord_domain, sk, attempt).await;
        match disp {
            Disposition::Done(resp) => return Ok(*resp),
            Disposition::Permanent {
                status,
                error,
                body,
            } => {
                return Err(RegisterError::Permanent {
                    status,
                    error,
                    body,
                });
            }
            Disposition::Transient { reason, hint } => {
                // If coord suggested a delay (e.g. 429 retry_after),
                // honor at least that — bumped by jitter and clamped
                // to the cap. Otherwise use our growing backoff.
                let mut next = if let Some(secs) = hint {
                    Duration::from_secs(secs).max(wait)
                } else {
                    wait
                };
                if next > policy.cap {
                    next = policy.cap;
                }
                let jittered = jitter(next);
                warn!(
                    attempt,
                    reason = %reason,
                    wait_ms = jittered.as_millis() as u64,
                    "register: backing off before retry"
                );
                tokio::select! {
                    _ = tokio::time::sleep(jittered) => {}
                    _ = shutdown.changed() => return Err(RegisterError::Cancelled),
                }
                // Grow the next wait toward the cap.
                wait = (wait.checked_mul(policy.multiplier).unwrap_or(policy.cap)).min(policy.cap);
            }
        }
    }
}

async fn attempt_register(
    coord_url: &str,
    coord_domain: &str,
    sk: &SigningKey,
    attempt: u32,
) -> Disposition {
    info!(attempt, "register: attempting POST /v1/register");
    match register(coord_url, coord_domain, sk).await {
        Ok(resp) => Disposition::Done(Box::new(resp)),
        Err(RegisterError::Coord { status, body }) => classify_status(status, body),
        Err(e @ RegisterError::Clock(_)) => Disposition::Permanent {
            status: 0,
            error: "clock_before_epoch".into(),
            body: e.to_string(),
        },
        Err(e @ RegisterError::Identity(_)) => Disposition::Permanent {
            status: 0,
            error: "identity_failed".into(),
            body: e.to_string(),
        },
        Err(RegisterError::Http(e)) => {
            // Network error — connect failed, TLS hiccup, server hung
            // up mid-response. All transient. reqwest::Error doesn't
            // expose a stable taxonomy across versions, so we rely on
            // the response status (handled above) to distinguish
            // permanent HTTP outcomes.
            Disposition::Transient {
                reason: format!("transport: {e}"),
                hint: None,
            }
        }
        // The retry loop is the only producer of these — `register()`
        // never builds them — so the arms are unreachable in practice.
        // Cover them defensively rather than panicking.
        Err(e @ RegisterError::Permanent { .. }) | Err(e @ RegisterError::Cancelled) => {
            Disposition::Permanent {
                status: 0,
                error: "internal".into(),
                body: e.to_string(),
            }
        }
    }
}

/// Decide retry vs. give-up from an HTTP status + body. Body parsing
/// is best-effort — coord's contract is JSON `{"error": "..."}`,
/// but we tolerate plain text too.
fn classify_status(status: u16, body: String) -> Disposition {
    let parsed: Option<CoordErrorBody> = serde_json::from_str(&body).ok();
    let error_code = parsed
        .as_ref()
        .and_then(|p| p.error.clone())
        .unwrap_or_default();
    match status {
        // 410 revoked — operator must un-revoke. Retrying spams coord.
        410 => Disposition::Permanent {
            status,
            error: if error_code.is_empty() {
                "revoked".into()
            } else {
                error_code
            },
            body,
        },
        // 400s: invalid_signature / pubkey_bad_length / clock_skew —
        // none are healed by a quiet retry. Surface to ops.
        400 => Disposition::Permanent {
            status,
            error: if error_code.is_empty() {
                "bad_request".into()
            } else {
                error_code
            },
            body,
        },
        // 429 rate_limited — server tells us when to try again.
        429 => {
            let hint = parsed.as_ref().and_then(|p| p.retry_after);
            Disposition::Transient {
                reason: format!("rate_limited (retry_after={hint:?})"),
                hint,
            }
        }
        // 500 alias_exhausted is permanent at coord; everything else
        // 5xx is a transient coord blip.
        500 if error_code == "alias_exhausted" => Disposition::Permanent {
            status,
            error: error_code,
            body,
        },
        500..=599 => Disposition::Transient {
            reason: format!("server_error {status}"),
            hint: None,
        },
        // 408 request timeout, 425 too early — treat as transient.
        408 | 425 => Disposition::Transient {
            reason: format!("transient {status}"),
            hint: None,
        },
        // Anything else (401/403/404 etc.) is operator-actionable and
        // shouldn't silently retry forever.
        _ => Disposition::Permanent {
            status,
            error: if error_code.is_empty() {
                format!("http_{status}")
            } else {
                error_code
            },
            body,
        },
    }
}

fn jitter(base: Duration) -> Duration {
    let base_ms = base.as_millis() as i64;
    let span = base_ms / 5; // ±20 %
    let jitter: i64 = if span == 0 {
        0
    } else {
        rand::thread_rng().gen_range(-span..=span)
    };
    let raw = (base_ms + jitter).max(100);
    Duration::from_millis(raw as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn build_request_fields_are_b64url_and_valid() {
        let sk = p2claw_identity::SigningKey::generate();
        let req = build_request(&sk, "coord.example", 1_767_312_000).unwrap();

        // pubkey_b64url decodes to 32 bytes matching the signer's peer_id.
        let pk = URL_SAFE_NO_PAD.decode(&req.pubkey_b64url).unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(&pk[..], sk.peer_id().as_bytes());

        // signature_b64url decodes to 64 bytes.
        let sig = URL_SAFE_NO_PAD.decode(&req.signature_b64url).unwrap();
        assert_eq!(sig.len(), 64);

        assert_eq!(req.timestamp, 1_767_312_000);
    }

    #[test]
    fn build_request_signature_verifies() {
        use p2claw_identity::Signature;

        let sk = p2claw_identity::SigningKey::generate();
        let coord = "coord.p2claw.com";
        let ts = 1_767_312_000u64;
        let req = build_request(&sk, coord, ts).unwrap();

        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&req.signature_b64url)
            .unwrap()
            .try_into()
            .unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        p2claw_identity::verify_registration(&sk.peer_id(), coord, ts, &sig, ts)
            .expect("signature should verify");
    }

    #[test]
    fn classify_410_is_permanent() {
        let d = classify_status(410, r#"{"error":"revoked"}"#.into());
        assert!(
            matches!(d, Disposition::Permanent { status: 410, .. }),
            "{d:?}"
        );
    }

    #[test]
    fn classify_400_invalid_sig_is_permanent() {
        let d = classify_status(400, r#"{"error":"invalid_signature"}"#.into());
        match d {
            Disposition::Permanent { status, error, .. } => {
                assert_eq!(status, 400);
                assert_eq!(error, "invalid_signature");
            }
            _ => panic!("{d:?}"),
        }
    }

    #[test]
    fn classify_500_alias_exhausted_is_permanent() {
        let d = classify_status(500, r#"{"error":"alias_exhausted"}"#.into());
        match d {
            Disposition::Permanent { status, error, .. } => {
                assert_eq!(status, 500);
                assert_eq!(error, "alias_exhausted");
            }
            _ => panic!("{d:?}"),
        }
    }

    #[test]
    fn classify_other_500_is_transient() {
        let d = classify_status(503, "server down".into());
        assert!(
            matches!(d, Disposition::Transient { hint: None, .. }),
            "{d:?}"
        );
    }

    #[test]
    fn classify_429_carries_retry_after_hint() {
        let d = classify_status(429, r#"{"error":"rate_limited","retry_after":7}"#.into());
        match d {
            Disposition::Transient { hint, .. } => assert_eq!(hint, Some(7)),
            _ => panic!("{d:?}"),
        }
    }

    #[test]
    fn classify_429_without_hint_is_transient_no_hint() {
        let d = classify_status(429, "rate limited".into());
        match d {
            Disposition::Transient { hint, .. } => assert_eq!(hint, None),
            _ => panic!("{d:?}"),
        }
    }

    #[test]
    fn classify_unknown_4xx_is_permanent() {
        // 401/403/404 — operator-actionable, shouldn't retry forever.
        for status in [401u16, 403, 404] {
            let d = classify_status(status, "{}".into());
            assert!(
                matches!(d, Disposition::Permanent { .. }),
                "status {status}: {d:?}"
            );
        }
    }

    #[test]
    fn jitter_stays_in_window() {
        for base in [Duration::from_millis(1_000), Duration::from_millis(60_000)] {
            for _ in 0..32 {
                let v = jitter(base).as_millis() as i64;
                let lower = (base.as_millis() as i64 - base.as_millis() as i64 / 5).max(100);
                let upper = base.as_millis() as i64 + base.as_millis() as i64 / 5;
                assert!(
                    v >= lower && v <= upper,
                    "base {base:?}: jitter {v} out of [{lower}, {upper}]"
                );
            }
        }
    }

    #[test]
    fn jitter_floor_is_100ms() {
        // Tiny base clamps to 100ms.
        let v = jitter(Duration::from_millis(10));
        assert!(v >= Duration::from_millis(100), "got {v:?}");
    }

    #[test]
    fn response_maps_to_state() {
        // Recognizable non-zero pubkey (`0xCD; 32`) so the
        // `From` impl's b64url decode is exercised, not the
        // sentinel-fallback branch.
        let coord_pk_bytes: [u8; 32] = [0xCD; 32];
        let coord_pk_b64 = B64_URL.encode(coord_pk_bytes);
        let r = RegisterResponse {
            peer_id: "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu".into(),
            alias: "y9abcdefghijk".into(),
            parent_domain: "p2claw.com".into(),
            // `control_url` is opaque to the agent (we dial coord
            // via QUIC on `coord_root_pubkey`'s NodeID, not this URL);
            // kept as an arbitrary string to mirror what coord still
            // emits on the wire pending the upgrade-auth rework that
            // drops both `control_url` and `control_token` from
            // RegisterResponse.
            control_url: "https://coord.p2claw.com/v1/register".into(),
            control_token: "tkn".into(),
            coord_domain: "coord.p2claw.com".into(),
            coord_root_pubkey_b64url: coord_pk_b64,
            // Coord-side iroh addressing on the wire. Cover the
            // populated branch so the From<...>
            // copy-through is exercised; the empty-default branch
            // is covered by `response_with_malformed_coord_pubkey_falls_back_to_sentinel`
            // and the explicit legacy-state test in state_store.
            iroh_relay_url: Some("https://relay.example.net/".into()),
            iroh_direct_addrs: vec!["198.51.100.1:55001".into()],
        };
        let s: AgentState = r.into();
        assert_eq!(s.alias, "y9abcdefghijk");
        assert_eq!(s.coord_domain, "coord.p2claw.com");
        assert_eq!(s.parent_domain, "p2claw.com");
        assert_eq!(
            s.coord_root_pubkey.as_bytes(),
            &coord_pk_bytes,
            "coord_root_pubkey must round-trip through b64url decode"
        );
        // Iroh addrs flow through unchanged — From is a straight copy.
        assert_eq!(
            s.coord_iroh_relay_url.as_deref(),
            Some("https://relay.example.net/")
        );
        assert_eq!(
            s.coord_iroh_direct_addrs,
            vec!["198.51.100.1:55001".to_string()]
        );
        // `control_token` is present on the wire but AgentState
        // doesn't store it.
    }

    #[test]
    fn response_with_malformed_coord_pubkey_falls_back_to_sentinel() {
        // Coord-side regression guard: if the b64url is malformed,
        // the agent surfaces a warn! and persists the all-zero
        // sentinel rather than crashing. The dial site refuses to
        // connect against an all-zero NodeID.
        let r = RegisterResponse {
            peer_id: "y9abc".into(),
            alias: "y9abc".into(),
            parent_domain: "p2claw.com".into(),
            control_url: "".into(),
            control_token: "".into(),
            coord_domain: "coord.p2claw.com".into(),
            coord_root_pubkey_b64url: "not-valid-base64!!!".into(),
            // Empty addrs branch: covers the older-coord / pre-mirror
            // path. From<...> still copies these through (None +
            // empty Vec); coord_conn dial would then either
            // discovery-resolve (default-relay mode, OK) or fail
            // (hermetic mode — the bug-of-record this work fixes).
            iroh_relay_url: None,
            iroh_direct_addrs: Vec::new(),
        };
        let s: AgentState = r.into();
        assert_eq!(s.coord_root_pubkey.as_bytes(), &[0u8; 32]);
        assert!(s.coord_iroh_relay_url.is_none());
        assert!(s.coord_iroh_direct_addrs.is_empty());
    }

    // ---- /v1/coord-self response parsing ----------------
    //
    // JSON-shape parsing only: `endpoint_id` is a `String` here and
    // the z-base-32 decode happens in `coord_conn::try_refresh_coord_self`,
    // so a wrong decoder there (`from_str` vs `from_z32` use disjoint
    // base-32 alphabets) would sail through these tests. The decode
    // contract is covered against real coord output elsewhere.

    /// Pin the wire shape of the coordination server's
    /// `/v1/self` response. If the JSON shape changes, this test
    /// fires so the agent-side struct and the consuming `coord_conn`
    /// recovery get updated together.
    #[test]
    fn coord_self_response_parses_documented_shape() {
        let body = r#"{
            "endpoint_id": "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq",
            "direct_addrs": ["10.0.2.34:42264", "192.168.1.5:8444"],
            "relay_url": null
        }"#;
        let r: CoordSelfResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            r.endpoint_id,
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq"
        );
        assert_eq!(r.direct_addrs.len(), 2);
        assert_eq!(r.direct_addrs[0], "10.0.2.34:42264");
        assert!(r.relay_url.is_none());
    }

    #[test]
    fn coord_self_response_with_relay_url_parses() {
        // Production direct-only deployment emits relay_url: null;
        // the relay-enabled path emits a string. Pin both shapes.
        let body = r#"{
            "endpoint_id": "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq",
            "direct_addrs": [],
            "relay_url": "https://relay.example.net/"
        }"#;
        let r: CoordSelfResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.relay_url.as_deref(), Some("https://relay.example.net/"));
        assert!(
            r.direct_addrs.is_empty(),
            "cold-start coord may publish no direct addrs yet"
        );
    }

    #[test]
    fn coord_self_response_tolerates_missing_optional_fields() {
        // Defense in depth: if coord switches to omitting nullish
        // fields rather than emitting `null`, the `#[serde(default)]`
        // on direct_addrs + relay_url accepts both shapes.
        let body = r#"{ "endpoint_id": "stub" }"#;
        let r: CoordSelfResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.endpoint_id, "stub");
        assert!(r.direct_addrs.is_empty());
        assert!(r.relay_url.is_none());
    }

    // ---- integration tests for register_with_retry ----------------
    //
    // Spin up a tiny TCP listener that speaks just enough HTTP/1.1 to
    // drive reqwest. Avoids pulling in a real hyper server here and
    // keeps the test surface focused on the retry loop's policy: how
    // many attempts coord sees, and whether permanent statuses
    // short-circuit.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    fn http_response(status_line: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "HTTP/1.1 {status_line}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    fn happy_body() -> Vec<u8> {
        // Match coord-side `RegisterResponse` shape: now
        // includes `coord_root_pubkey_b64url`. Recognizable
        // 0xEF-byte stand-in pubkey.
        let coord_pk_b64 = B64_URL.encode([0xEFu8; 32]);
        let json = serde_json::json!({
            "peer_id": "y9abcdefghijkmnopqrstuvwxyz234567abcdefghijkmnopqrstu",
            "alias": "calm-river-hat",
            "parent_domain": "p2claw.com",
            // Opaque to the agent (we use coord_root_pubkey for the
            // QUIC dial). See sibling note in the in-memory test
            // fixture above.
            "control_url": "https://coord.p2claw.com/v1/register",
            "control_token": "tkn-1",
            "coord_domain": "coord.p2claw.com",
            "coord_root_pubkey_b64url": coord_pk_b64,
        });
        serde_json::to_vec(&json).unwrap()
    }

    /// Mini coord that returns the canned response from `responses` in
    /// order, looping the last one for any extra connections. The
    /// returned counter records the number of accepted connections.
    async fn spawn_mock_coord(responses: Vec<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_server = Arc::clone(&counter);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let n = counter_for_server.fetch_add(1, Ordering::SeqCst);
                // Drain the request best-effort so reqwest's POST
                // completes; we don't actually parse it.
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = responses
                    .get(n)
                    .cloned()
                    .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                let _ = s.write_all(&resp).await;
                let _ = s.shutdown().await;
            }
        });
        (port, counter)
    }

    /// Tight retry policy so the test doesn't sleep noticeably.
    fn fast_policy() -> RegisterRetryPolicy {
        RegisterRetryPolicy {
            base: Duration::from_millis(10),
            cap: Duration::from_millis(40),
            multiplier: 2,
        }
    }

    #[tokio::test]
    async fn register_with_retry_succeeds_after_two_503s() {
        let responses = vec![
            http_response("503 Service Unavailable", b""),
            http_response("503 Service Unavailable", b""),
            http_response("200 OK", &happy_body()),
        ];
        let (port, counter) = spawn_mock_coord(responses).await;

        let sk = SigningKey::generate();
        let coord_url = format!("http://127.0.0.1:{port}");
        let (_sd_tx, sd_rx) = watch::channel(false);

        let resp = register_with_retry(&coord_url, "coord.p2claw.com", &sk, fast_policy(), sd_rx)
            .await
            .expect("retry loop should succeed on the third attempt");
        assert_eq!(resp.alias, "calm-river-hat");
        assert!(
            counter.load(Ordering::SeqCst) >= 3,
            "expected ≥3 coord attempts, saw {}",
            counter.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn register_with_retry_410_revoked_is_permanent_no_retry() {
        let responses = vec![http_response("410 Gone", br#"{"error":"revoked"}"#)];
        let (port, counter) = spawn_mock_coord(responses).await;

        let sk = SigningKey::generate();
        let coord_url = format!("http://127.0.0.1:{port}");
        let (_sd_tx, sd_rx) = watch::channel(false);

        let err = register_with_retry(&coord_url, "coord.p2claw.com", &sk, fast_policy(), sd_rx)
            .await
            .expect_err("410 must surface as a permanent error");
        match err {
            RegisterError::Permanent { status, error, .. } => {
                assert_eq!(status, 410);
                assert_eq!(error, "revoked");
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "permanent failure must not retry"
        );
    }

    #[tokio::test]
    async fn register_with_retry_429_honors_retry_after_hint() {
        // First response: 429 with a retry_after that exceeds our base.
        // Second response: 200. Assert the loop respected the hint
        // (i.e. waited at least the hinted duration before attempting
        // again) and ultimately succeeded.
        let responses = vec![
            http_response(
                "429 Too Many Requests",
                br#"{"error":"rate_limited","retry_after":1}"#,
            ),
            http_response("200 OK", &happy_body()),
        ];
        let (port, counter) = spawn_mock_coord(responses).await;

        let sk = SigningKey::generate();
        let coord_url = format!("http://127.0.0.1:{port}");
        let (_sd_tx, sd_rx) = watch::channel(false);
        // base 10ms, cap 2s — without the hint we'd retry in ~10ms.
        // With retry_after=1, we should wait ≈1s (±20% jitter, floor 800ms).
        let policy = RegisterRetryPolicy {
            base: Duration::from_millis(10),
            cap: Duration::from_secs(2),
            multiplier: 2,
        };
        let started = std::time::Instant::now();
        let resp = register_with_retry(&coord_url, "coord.p2claw.com", &sk, policy, sd_rx)
            .await
            .expect("should succeed after honoring 429");
        let elapsed = started.elapsed();
        assert_eq!(resp.alias, "calm-river-hat");
        assert!(
            elapsed >= Duration::from_millis(700),
            "should have waited ≈1s (±20% jitter) — saw {elapsed:?}"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn register_with_retry_cancels_on_shutdown() {
        // Coord always returns 503 — without shutdown the loop would
        // retry forever. Flip shutdown after a moment and assert the
        // loop returns Cancelled rather than continuing to spin.
        let responses = vec![http_response("503 Service Unavailable", b"")];
        let (port, _counter) = spawn_mock_coord(responses).await;

        let sk = SigningKey::generate();
        let coord_url = format!("http://127.0.0.1:{port}");
        let (sd_tx, sd_rx) = watch::channel(false);

        let handle = tokio::spawn({
            let coord_url = coord_url.clone();
            async move {
                register_with_retry(&coord_url, "coord.p2claw.com", &sk, fast_policy(), sd_rx).await
            }
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        sd_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("cancellation should land within 2s")
            .expect("retry task should not panic");
        assert!(
            matches!(result, Err(RegisterError::Cancelled)),
            "expected Cancelled, got {result:?}"
        );
    }
}
