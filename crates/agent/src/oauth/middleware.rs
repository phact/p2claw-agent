//! Per-request OAuth middleware.
//!
//! Called from [`crate::forwarder::Forwarder::dispatch`] AFTER the
//! Host → app resolution but BEFORE the upstream dial. Two
//! responsibilities:
//!
//! 1. **Always strip incoming `X-P2claw-*` headers.** Even on
//!    public apps, an attacker who can hit the box must not be
//!    able to fake identity headers the upstream might trust.
//!    Belt-and-braces; runs regardless of `requires_auth`.
//! 2. **When the app is auth-gated**: extract the JWT from
//!    `Cookie: __p2claw_session=…` or `Authorization: Bearer …`,
//!    validate via [`super::jwt::validate`] against the JWKS
//!    cache, on success strip the credential + inject
//!    `X-P2claw-User/Email/Name/Picture`, on failure return `401`
//!    with `P2claw-Auth-Required: true` for the bootstrap-side
//!    listener to react to.
//!
//! [`apply`] takes the mutable request shell + the validator and
//! returns `Ok(AuthOutcome)` (request now ready to forward) or
//! `Err(MiddlewareError)` carrying a [`p2claw_translator::ServerResponse`]
//! the dispatcher returns to the caller.

use bytes::Bytes;
use p2claw_control_proto::AuthMethod;
use p2claw_translator::{OutgoingBody, ServerRequest, ServerResponse};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

use super::{
    device, jwt, AUTH_REQUIRED_HEADER, AUTH_REQUIRED_VALUE, HEADER_EMAIL, HEADER_NAME,
    HEADER_PICTURE, HEADER_PROVIDER, HEADER_USER, IDENTITY_HEADER_PREFIX, SESSION_COOKIE_NAME,
};
use crate::attestation;
use crate::oauth::OAuthValidator;
use p2claw_identity::SigningKey;

/// Outcome of a successful middleware run. The forwarder passes
/// through to the upstream; identity (when applicable) is now on
/// the request as `X-P2claw-*` headers.
#[derive(Debug, Clone, Copy)]
pub enum AuthOutcome {
    /// App doesn't require auth (`auth: []`). The `X-P2claw-*`
    /// spoof strip ran; if the request carried a valid session
    /// credential, identity headers were injected opportunistically
    /// (see the public-route branch in [`apply`]).
    Public,
    /// App required auth + at least one method validated; identity
    /// headers injected.
    Authenticated,
}

#[derive(Debug, Error)]
pub enum MiddlewareError {
    /// Missing or invalid credentials on a method-gated route. Maps
    /// to `401 + P2claw-Auth-Required: true`. `accepted_methods`
    /// names the method kinds the route lists, surfaced in the
    /// response body so a hand-rolling caller (`curl`) sees what
    /// would have worked.
    #[error("auth required (accepted methods: {accepted_methods:?}): {detail}")]
    AuthRequired {
        accepted_methods: Vec<String>,
        detail: String,
    },
    /// JWKS unavailable (cache empty + broker unreachable). Maps
    /// to `503 + P2claw-Auth-Required: true`.
    #[error("auth backend unavailable: {0}")]
    AuthBackendUnavailable(String),
    /// Route lists ONLY auth methods the daemon doesn't yet
    /// implement (e.g. v3 box on a fleet that just added
    /// `SignedLink`). Maps to `501 Not Implemented` — distinct
    /// from "auth required" because the visitor can't satisfy
    /// the gate from their side either; the daemon needs to be
    /// upgraded. Only fires when EVERY listed method is
    /// unimplemented; a mixed list `[Oauth, SignedLink]` still
    /// tries `Oauth` and returns 401 on failure (not 501).
    #[error("auth methods not implemented: {kinds:?}")]
    MethodsNotImplemented { kinds: Vec<String> },
}

impl MiddlewareError {
    /// Convert into the [`ServerResponse`] the forwarder returns
    /// to the visitor's transport. All branches set
    /// `P2claw-Auth-Required: true` so the bootstrap can
    /// react identically regardless of which auth-side failure
    /// triggered the rejection.
    pub fn into_response(self) -> ServerResponse {
        let status = match &self {
            Self::AuthRequired { .. } => 401,
            Self::AuthBackendUnavailable(_) => 503,
            Self::MethodsNotImplemented { .. } => 501,
        };
        let body = match &self {
            Self::AuthRequired {
                accepted_methods, ..
            } => format!(
                "authentication required (accepted methods: {})\n",
                accepted_methods.join(", ")
            ),
            Self::AuthBackendUnavailable(_) => "auth backend unavailable\n".to_string(),
            Self::MethodsNotImplemented { kinds } => format!(
                "this app requires auth methods this daemon does not implement: {}. \
                 Upgrade the agent on that machine.\n",
                kinds.join(", ")
            ),
        };
        ServerResponse::new(status)
            .header(
                Bytes::from_static(AUTH_REQUIRED_HEADER.as_bytes()),
                Bytes::from_static(AUTH_REQUIRED_VALUE.as_bytes()),
            )
            .header(
                Bytes::from_static(b"content-type"),
                Bytes::from_static(b"text/plain; charset=utf-8"),
            )
            .with_body(OutgoingBody::once(Bytes::from(body)))
    }
}

/// Apply the middleware to a request in-place. Returns
/// [`AuthOutcome`] on success or an error carrying the rejection
/// shape.
///
/// `auth` is the route's method list per `RouteRecord.auth`
/// Empty = public — only the header strip runs. Otherwise
/// iterate methods in order; first one that succeeds wins
/// (strips its credential + injects identity headers + returns
/// `Authenticated`). No method matches → `AuthRequired` carrying
/// the kind list for the response body; ALL methods are
/// unimplemented (e.g. v3 box on a fleet that just added
/// `SignedLink`) → `MethodsNotImplemented` (501).
pub async fn apply(
    req: &mut ServerRequest,
    auth: &[AuthMethod],
    validator: Option<&Arc<OAuthValidator>>,
    identity: Option<&Arc<SigningKey>>,
) -> Result<AuthOutcome, MiddlewareError> {
    // Step 0: capture the device-cert proof-of-possession headers
    // BEFORE the identity strip removes them. They are `x-p2claw-*`
    // (so the strip below covers them, keeping them off the upstream)
    // but the device-cert path still needs to read them.
    let device_pop = DevicePop::capture(req);

    // Step 1: ALWAYS strip incoming X-P2claw-* headers. Runs even
    // on public apps — defense-in-depth so an attacker who can
    // hit the box can't fake identity headers. The same prefix strip
    // covers the new `X-P2claw-Identity-Token` and `X-P2claw-Box-Id`
    // headers `crate::attestation::inject` adds below, plus the
    // `X-P2claw-Device-*` PoP headers just captured.
    strip_identity_headers(req);

    if auth.is_empty() {
        // Public route — but identity is still offered when the
        // visitor has one. An app can gate part of itself by
        // sending visitors through `/__p2claw/bootstrap` and then
        // branching on `X-P2claw-User`; the broker mints sessions
        // for any app host, so the cookie shows up here even though
        // the route has no gate. A valid credential is stripped and
        // swapped for identity headers exactly as on a gated route.
        // Anything else — no credential, bad credential, JWKS
        // unreachable — falls through untouched: a public route
        // never fails on auth machinery.
        if extract_jwt(req).is_some() {
            if let Ok(claims) = try_oauth(req, None, validator, device_pop.as_ref()).await {
                strip_credential(req);
                inject_identity_headers(req, &claims);
                if let Some(signer) = identity {
                    attestation::inject(req, signer, &claims);
                }
            }
        }
        return Ok(AuthOutcome::Public);
    }

    // Track per-method outcomes so we can distinguish "401 —
    // tried everything, none accepted" from "501 — daemon doesn't
    // know how to evaluate ANY of the listed methods." Today only
    // `Oauth` is implemented so the implemented-counter stays 0
    // only if the route has solely future-variant entries (which
    // can't happen until those variants are added to `AuthMethod`).
    let mut last_detail = String::new();
    let mut implemented_methods_tried = 0usize;
    let kinds: Vec<String> = auth.iter().map(method_kind_name).collect();

    for method in auth {
        match method {
            AuthMethod::Oauth { providers } => {
                implemented_methods_tried += 1;
                match try_oauth(req, providers.as_deref(), validator, device_pop.as_ref()).await {
                    Ok(claims) => {
                        // Success — strip the credential, inject
                        // identity, short-circuit. Caller forwards.
                        strip_credential(req);
                        inject_identity_headers(req, &claims);
                        if let Some(signer) = identity {
                            attestation::inject(req, signer, &claims);
                        }
                        return Ok(AuthOutcome::Authenticated);
                    }
                    Err(TryOauthError::BackendUnavailable(reason)) => {
                        // JWKS cache empty + broker unreachable.
                        // Surface as 503 immediately — no point
                        // trying other methods, since this is an
                        // infra problem.
                        return Err(MiddlewareError::AuthBackendUnavailable(reason));
                    }
                    Err(TryOauthError::Reject(detail)) => {
                        // Bad / missing JWT, or `claims.provider`
                        // mismatch against the per-method
                        // `providers` filter. Try the next method
                        // (typical case: only one Oauth entry, so
                        // we fall through to the AuthRequired
                        // return at the bottom).
                        last_detail = detail;
                    }
                }
            } // future variants land here without code change above;
              // the implemented_methods_tried counter stays at 0 in
              // that branch so 501 surfaces below.
        }
    }

    if implemented_methods_tried == 0 {
        return Err(MiddlewareError::MethodsNotImplemented { kinds });
    }
    Err(MiddlewareError::AuthRequired {
        accepted_methods: kinds,
        detail: if last_detail.is_empty() {
            "no method accepted the credentials".into()
        } else {
            last_detail
        },
    })
}

/// Per-method outcome for [`try_oauth`]. Internal — surfaces into
/// the right [`MiddlewareError`] arm in [`apply`].
enum TryOauthError {
    /// Reject: bad signature, expired token, aud/iss mismatch,
    /// provider-filter miss, etc. Caller continues to the next
    /// method (if any) or maps to 401.
    Reject(String),
    /// JWKS cache empty + broker unreachable. Caller short-circuits
    /// to 503 — no point trying other methods on an infra fault.
    BackendUnavailable(String),
}

/// Try OAuth validation against the JWKS cache + provider filter.
/// Pulled out of [`apply`] so the iterate-methods loop reads
/// cleanly + so the future `SignedLink`/`OneTime` variants get
/// their own sibling helpers without ballooning `apply`.
async fn try_oauth(
    req: &ServerRequest,
    providers_filter: Option<&[String]>,
    validator: Option<&Arc<OAuthValidator>>,
    device_pop: Option<&DevicePop>,
) -> Result<jwt::Claims, TryOauthError> {
    let validator = match validator {
        Some(v) => v,
        None => {
            warn!(
                "oauth::middleware: Oauth method present but no validator wired — \
                 returning backend-unavailable. This is a daemon bug."
            );
            return Err(TryOauthError::BackendUnavailable(
                "oauth validator not initialised".into(),
            ));
        }
    };

    let token = match extract_jwt(req) {
        Some(t) => t,
        None => {
            debug!("oauth::middleware: Oauth method gated but no JWT presented");
            return Err(TryOauthError::Reject(
                "no session cookie or bearer token".into(),
            ));
        }
    };

    let config = validator.config();
    let jwks = validator.jwks().clone();
    let kid = match peek_kid(&token) {
        Some(k) => k,
        None => return Err(TryOauthError::Reject("jwt header missing kid".into())),
    };

    let verifying_key = jwks.lookup_with_retry(&kid).await;
    if verifying_key.is_none() {
        // Distinguish "cache empty + can't fetch" (503) from
        // "cache populated but key genuinely unknown" (401).
        if let Err(super::jwks::JwksError::Unavailable(reason)) = jwks.current().await {
            return Err(TryOauthError::BackendUnavailable(reason));
        }
    }

    // Dispatch on the JWT `typ`: a device-binding cert takes the
    // device path (sentinel aud + proof-of-possession); anything
    // else is the browser/session path below.
    if device::is_device_cert(&token) {
        return try_device_cert(
            &token,
            &kid,
            verifying_key,
            config.expected_iss(),
            providers_filter,
            device_pop,
            validator.replay().as_ref(),
        );
    }

    let claims = match jwt::validate(
        &token,
        config.expected_iss(),
        &config.expected_aud_z32,
        jwt::unix_now,
        |k| if k == kid { verifying_key } else { None },
    ) {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "oauth::middleware: jwt validation failed");
            return Err(TryOauthError::Reject(e.to_string()));
        }
    };

    // Per-method `providers` filter. `None` (or absent on
    // wire) means "any provider the broker has configured"; a
    // populated list restricts to those keys.
    if let Some(allowed) = providers_filter {
        if !allowed.iter().any(|p| p == &claims.provider) {
            debug!(
                provider = %claims.provider,
                allowed = ?allowed,
                "oauth::middleware: token's provider not in this method's allowlist"
            );
            return Err(TryOauthError::Reject(format!(
                "token provider `{}` not in this app's allowed providers ({:?})",
                claims.provider, allowed
            )));
        }
    }

    Ok(claims)
}

/// The device-cert path: validate the long-lived broker cert, verify
/// the per-request proof of possession against the cert's
/// `device_key`, apply the provider filter, and return the identity
/// as a [`jwt::Claims`] so the caller injects headers identically to
/// the session path. `verifying_key` is the JWKS entry already looked
/// up by `kid`.
fn try_device_cert(
    token: &str,
    kid: &str,
    verifying_key: Option<ed25519_dalek::VerifyingKey>,
    expected_iss: &str,
    providers_filter: Option<&[String]>,
    device_pop: Option<&DevicePop>,
    replay: &device::ReplayCache,
) -> Result<jwt::Claims, TryOauthError> {
    let claims = device::validate_cert(token, expected_iss, jwt::unix_now, |k| {
        if k == kid {
            verifying_key
        } else {
            None
        }
    })
    .map_err(|e| {
        debug!(error = %e, "oauth::middleware: device cert validation failed");
        TryOauthError::Reject(e.to_string())
    })?;

    // Cert is authentic — now require the proof of possession.
    let pop = device_pop.ok_or_else(|| {
        TryOauthError::Reject("device cert presented without proof-of-possession headers".into())
    })?;
    device::verify_pop(
        &claims.device_key,
        &pop.sig,
        &pop.ts,
        &pop.nonce,
        device::unix_now(),
        replay,
    )
    .map_err(|e| {
        debug!(error = %e, "oauth::middleware: device PoP verification failed");
        TryOauthError::Reject(e.to_string())
    })?;

    if let Some(allowed) = providers_filter {
        if !allowed.iter().any(|p| p == &claims.provider) {
            return Err(TryOauthError::Reject(format!(
                "token provider `{}` not in this app's allowed providers ({:?})",
                claims.provider, allowed
            )));
        }
    }

    // Identity is identical in shape to a session token — reuse the
    // existing injectors + attestation by handing back a `jwt::Claims`.
    Ok(jwt::Claims {
        iss: claims.iss,
        aud: claims.aud,
        sub: claims.sub,
        email: claims.email,
        email_verified: claims.email_verified,
        name: claims.name,
        picture: claims.picture,
        provider: claims.provider,
        iat: claims.iat,
        exp: claims.exp,
    })
}

/// Device-cert proof-of-possession, lifted off the `X-P2claw-Device-*`
/// request headers before they are stripped.
struct DevicePop {
    sig: String,
    ts: String,
    nonce: String,
}

impl DevicePop {
    /// Read the three PoP headers. Returns `None` unless all three
    /// are present (a partial set is treated as absent — the device
    /// path then rejects with "no proof of possession").
    fn capture(req: &ServerRequest) -> Option<Self> {
        let get = |want: &str| -> Option<String> {
            req.headers.iter().find_map(|(name, value)| {
                if eq_ascii_ci(name, want.as_bytes()) {
                    std::str::from_utf8(value).ok().map(str::to_string)
                } else {
                    None
                }
            })
        };
        Some(Self {
            sig: get(device::HEADER_DEVICE_SIG)?,
            ts: get(device::HEADER_DEVICE_TS)?,
            nonce: get(device::HEADER_DEVICE_NONCE)?,
        })
    }
}

/// Stable kind-name for a method, used in the 401 / 501 response
/// body so a `curl` operator can see what the gate accepts.
fn method_kind_name(m: &AuthMethod) -> String {
    match m {
        AuthMethod::Oauth { providers: None } => "oauth".into(),
        AuthMethod::Oauth { providers: Some(p) } => format!("oauth({})", p.join(",")),
    }
}

/// Remove every header whose name starts with `x-p2claw-` (case
/// insensitive). Defense-in-depth: even public apps shouldn't see
/// an attacker-controlled identity header. Also used by the
/// private-route gate in the forwarder, which strips-then-injects
/// `X-P2claw-Peer` instead of the OAuth identity set.
pub(crate) fn strip_identity_headers(req: &mut ServerRequest) {
    req.headers
        .retain(|(name, _)| !name_starts_with_ascii_ci(name, IDENTITY_HEADER_PREFIX));
}

/// Remove the `Cookie: __p2claw_session=…` entry + any
/// `Authorization` header. Same belt-and-braces logic as above:
/// don't leak the credential to the upstream even after a
/// successful validation.
fn strip_credential(req: &mut ServerRequest) {
    let mut rebuilt_cookies: Vec<Bytes> = Vec::new();
    let mut removed_authz = false;
    req.headers.retain(|(name, value)| {
        if eq_ascii_ci(name, b"authorization") {
            removed_authz = true;
            return false;
        }
        if eq_ascii_ci(name, b"cookie") {
            // Rebuild the Cookie value without the session cookie.
            if let Ok(s) = std::str::from_utf8(value) {
                let filtered: Vec<&str> = s
                    .split(';')
                    .map(str::trim)
                    .filter(|c| !c.starts_with(&format!("{SESSION_COOKIE_NAME}=")))
                    .filter(|c| !c.is_empty())
                    .collect();
                if !filtered.is_empty() {
                    rebuilt_cookies.push(Bytes::from(filtered.join("; ")));
                }
            }
            return false;
        }
        true
    });
    for c in rebuilt_cookies {
        req.headers.push((Bytes::from_static(b"cookie"), c));
    }
    if removed_authz {
        debug!("oauth::middleware: stripped Authorization header");
    }
}

fn inject_identity_headers(req: &mut ServerRequest, claims: &jwt::Claims) {
    req.headers.push((
        Bytes::from_static(HEADER_USER.as_bytes()),
        Bytes::from(pct_encode(&claims.sub)),
    ));
    req.headers.push((
        Bytes::from_static(HEADER_EMAIL.as_bytes()),
        Bytes::from(pct_encode(&claims.email)),
    ));
    if let Some(name) = claims.name.as_deref() {
        req.headers.push((
            Bytes::from_static(HEADER_NAME.as_bytes()),
            Bytes::from(pct_encode(name)),
        ));
    }
    if let Some(pic) = claims.picture.as_deref() {
        req.headers.push((
            Bytes::from_static(HEADER_PICTURE.as_bytes()),
            Bytes::from(pct_encode(pic)),
        ));
    }
    req.headers.push((
        Bytes::from_static(HEADER_PROVIDER.as_bytes()),
        Bytes::from(claims.provider.clone()),
    ));
}

/// Percent-encode a claim value so it is always a valid, ASCII-only
/// HTTP header value. Claim values like a user's display name can be
/// non-ASCII ("José", "山田太郎"); a raw non-ASCII header value breaks
/// HTTP/1.1 serialization across the ecosystem (tungstenite's `to_str`,
/// httpx, browser `Headers`), so we'd either crash the WS dial or hand
/// the upstream an unparseable header. Encoding every byte outside
/// printable ASCII (plus `%` itself, so decoding is unambiguous) keeps
/// the convenience headers wire-safe everywhere. Pure-ASCII values pass
/// through unchanged. Consumers percent-decode; the signed
/// `X-P2claw-Identity-Token` carries the exact UTF-8 claims as the
/// authoritative source.
fn pct_encode(s: &str) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        if (0x20..=0x7E).contains(&b) && b != b'%' {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0F) as usize]);
        }
    }
    out
}

/// Extract the JWT either from `Cookie: __p2claw_session=…` or
/// from `Authorization: Bearer <jwt>`. Prefers the cookie (the
/// browser path) but accepts
/// `Authorization` as a fallback for native CLI clients that
/// don't use cookies.
fn extract_jwt(req: &ServerRequest) -> Option<String> {
    // Cookie first.
    for (name, value) in &req.headers {
        if !eq_ascii_ci(name, b"cookie") {
            continue;
        }
        let Ok(s) = std::str::from_utf8(value) else {
            continue;
        };
        for crumb in s.split(';') {
            let crumb = crumb.trim();
            let prefix = format!("{SESSION_COOKIE_NAME}=");
            if let Some(rest) = crumb.strip_prefix(&prefix) {
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
    }
    // Authorization: Bearer …
    for (name, value) in &req.headers {
        if !eq_ascii_ci(name, b"authorization") {
            continue;
        }
        let Ok(s) = std::str::from_utf8(value) else {
            continue;
        };
        let trimmed = s.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Bearer ")
            .or_else(|| trimmed.strip_prefix("bearer "))
        {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Cheap kid peek — decodes JUST the header segment, no sig check.
/// Used to pre-fetch the JWKS entry before handing off to the
/// real validator.
fn peek_kid(token: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_b64 = token.split('.').next()?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    header.get("kid")?.as_str().map(String::from)
}

fn name_starts_with_ascii_ci(name: &[u8], prefix: &str) -> bool {
    let p = prefix.as_bytes();
    if name.len() < p.len() {
        return false;
    }
    name[..p.len()].eq_ignore_ascii_case(p)
}

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use p2claw_translator::IncomingBody;
    use rand::rngs::OsRng;
    use serde_json::json;

    fn empty_request() -> ServerRequest {
        ServerRequest {
            method: Bytes::from_static(b"GET"),
            path: Bytes::from_static(b"/"),
            headers: Vec::new(),
            body: IncomingBody::empty(),
        }
    }

    #[test]
    fn strip_identity_headers_drops_x_p2claw_prefix() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"X-P2claw-User"),
            Bytes::from_static(b"alice"),
        ));
        req.headers.push((
            Bytes::from_static(b"x-p2claw-email"),
            Bytes::from_static(b"alice@example"),
        ));
        req.headers
            .push((Bytes::from_static(b"X-Other"), Bytes::from_static(b"keep")));
        strip_identity_headers(&mut req);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0.as_ref(), b"X-Other");
    }

    #[test]
    fn strip_credential_removes_authz_and_session_cookie() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Authorization"),
            Bytes::from_static(b"Bearer xxx"),
        ));
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"keep=1; __p2claw_session=eyJhbGc; also=2"),
        ));
        strip_credential(&mut req);
        assert!(
            !req.headers
                .iter()
                .any(|(n, _)| eq_ascii_ci(n, b"authorization")),
            "authorization should be gone"
        );
        let cookie = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, b"cookie"))
            .expect("cookie remains for keep=1 and also=2");
        assert_eq!(cookie.1.as_ref(), b"keep=1; also=2");
    }

    #[test]
    fn strip_credential_removes_lone_session_cookie_entirely() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"__p2claw_session=xyz"),
        ));
        strip_credential(&mut req);
        assert!(
            !req.headers.iter().any(|(n, _)| eq_ascii_ci(n, b"cookie")),
            "cookie header gone when only the session crumb was present"
        );
    }

    #[test]
    fn extract_jwt_from_cookie() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"foo=bar; __p2claw_session=THE_TOKEN; other=1"),
        ));
        assert_eq!(extract_jwt(&req).as_deref(), Some("THE_TOKEN"));
    }

    #[test]
    fn extract_jwt_from_bearer() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Authorization"),
            Bytes::from_static(b"Bearer THE_TOKEN"),
        ));
        assert_eq!(extract_jwt(&req).as_deref(), Some("THE_TOKEN"));
    }

    #[test]
    fn extract_jwt_cookie_beats_bearer_when_both_present() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"__p2claw_session=COOKIE_TOKEN"),
        ));
        req.headers.push((
            Bytes::from_static(b"Authorization"),
            Bytes::from_static(b"Bearer HEADER_TOKEN"),
        ));
        assert_eq!(extract_jwt(&req).as_deref(), Some("COOKIE_TOKEN"));
    }

    #[test]
    fn extract_jwt_returns_none_when_absent() {
        let req = empty_request();
        assert!(extract_jwt(&req).is_none());
    }

    #[test]
    fn peek_kid_extracts_header_kid() {
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"the-kid"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let token = format!("{h_b64}.payload.sig");
        assert_eq!(peek_kid(&token).as_deref(), Some("the-kid"));
    }

    #[test]
    fn peek_kid_returns_none_on_garbage() {
        assert!(peek_kid("not a jwt").is_none());
    }

    #[test]
    fn pct_encode_passes_ascii_and_escapes_the_rest() {
        // Pure ASCII (incl. typical sub/email chars) is unchanged.
        assert_eq!(pct_encode("gh:42"), b"gh:42");
        assert_eq!(pct_encode("alice@example.com"), b"alice@example.com");
        // `%` is escaped so decoding is unambiguous.
        assert_eq!(pct_encode("100%"), b"100%25");
        // Non-ASCII display names: UTF-8 bytes percent-encoded, ASCII-only
        // output, and it round-trips back to the original.
        let encoded = pct_encode("José"); // 'é' = U+00E9 = C3 A9
        assert_eq!(encoded, b"Jos%C3%A9");
        assert!(encoded.iter().all(|&b| b.is_ascii_graphic()));
        // Round-trip via a standard percent-decode.
        let decoded = percent_decode_for_test(&encoded);
        assert_eq!(decoded, "José".as_bytes());
        // Control bytes are escaped too (header-injection safety).
        assert_eq!(pct_encode("a\r\nb"), b"a%0D%0Ab");
    }

    fn percent_decode_for_test(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() + 1 {
                let hi = (bytes[i + 1] as char).to_digit(16).unwrap();
                let lo = (bytes[i + 2] as char).to_digit(16).unwrap();
                out.push((hi * 16 + lo) as u8);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out
    }

    #[tokio::test]
    async fn apply_strips_headers_when_public_no_validator() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"X-P2claw-User"),
            Bytes::from_static(b"spoofed"),
        ));
        req.headers
            .push((Bytes::from_static(b"X-Keep"), Bytes::from_static(b"yes")));
        let outcome = apply(&mut req, &[], None, None).await.unwrap();
        assert!(matches!(outcome, AuthOutcome::Public));
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0.as_ref(), b"X-Keep");
    }

    #[tokio::test]
    async fn public_route_with_valid_session_injects_identity() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = jwt::unix_now();
        let claims = jwt::Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: "this-box-z32".into(),
            sub: "gh:42".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: Some("Alice".into()),
            picture: None,
            provider: "github".into(),
            iat: now,
            exp: now + 600,
        };
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{h_b64}.{p_b64}.{s_b64}");

        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box-z32".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;

        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from(format!("keep=1; __p2claw_session={token}")),
        ));

        let outcome = apply(&mut req, &[], Some(&validator), None).await.unwrap();
        assert!(matches!(outcome, AuthOutcome::Public));

        let user = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, HEADER_USER.as_bytes()))
            .map(|(_, v)| v.clone())
            .expect("X-P2claw-User present on public route with valid session");
        assert_eq!(user.as_ref(), b"gh:42");

        // Credential must not leak upstream; unrelated cookies stay.
        let cookie = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, b"cookie"))
            .map(|(_, v)| v.clone())
            .expect("non-session cookies survive");
        let cookie_str = std::str::from_utf8(cookie.as_ref()).unwrap();
        assert!(cookie_str.contains("keep=1"));
        assert!(!cookie_str.contains(SESSION_COOKIE_NAME));
    }

    #[tokio::test]
    async fn public_route_with_invalid_session_stays_public() {
        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box-z32".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        let sk = SigningKey::generate(&mut OsRng);
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;

        let mut req = empty_request();
        // Spoofed identity header — must be stripped regardless.
        req.headers.push((
            Bytes::from_static(b"X-P2claw-User"),
            Bytes::from_static(b"SPOOFED"),
        ));
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"__p2claw_session=not.a.jwt"),
        ));

        let outcome = apply(&mut req, &[], Some(&validator), None).await.unwrap();
        assert!(matches!(outcome, AuthOutcome::Public));
        assert!(
            !req.headers
                .iter()
                .any(|(n, _)| eq_ascii_ci(n, HEADER_USER.as_bytes())),
            "no identity headers on failed opportunistic validation"
        );
    }

    #[tokio::test]
    async fn public_route_with_session_but_no_validator_stays_public() {
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from_static(b"__p2claw_session=not.a.jwt"),
        ));
        let outcome = apply(&mut req, &[], None, None).await.unwrap();
        assert!(matches!(outcome, AuthOutcome::Public));
        assert!(!req
            .headers
            .iter()
            .any(|(n, _)| eq_ascii_ci(n, HEADER_USER.as_bytes())),);
    }

    #[tokio::test]
    async fn apply_returns_auth_required_when_no_jwt_present() {
        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "test-aud".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        let sk = SigningKey::generate(&mut OsRng);
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;
        let mut req = empty_request();
        let err = apply(&mut req, &[AuthMethod::oauth_any()], Some(&validator), None)
            .await
            .unwrap_err();
        assert!(matches!(err, MiddlewareError::AuthRequired { .. }));
        let resp = err.into_response();
        assert_eq!(resp.status, 401);
        let auth_required_header = resp
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, AUTH_REQUIRED_HEADER.as_bytes()))
            .map(|(_, v)| v.clone());
        assert_eq!(
            auth_required_header.as_deref(),
            Some(AUTH_REQUIRED_VALUE.as_bytes()),
            "P2claw-Auth-Required header must be set on 401"
        );
    }

    #[tokio::test]
    async fn apply_validates_and_injects_identity() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = jwt::unix_now();
        let claims = jwt::Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: "this-box-z32".into(),
            sub: "gh:42".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: Some("Alice".into()),
            picture: Some("https://avatars/x".into()),
            provider: "github".into(),
            iat: now,
            exp: now + 600,
        };
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{h_b64}.{p_b64}.{s_b64}");

        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box-z32".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;

        let mut req = empty_request();
        // Spoofed identity header — must be stripped.
        req.headers.push((
            Bytes::from_static(b"X-P2claw-User"),
            Bytes::from_static(b"SPOOFED"),
        ));
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from(format!("keep=1; __p2claw_session={token}")),
        ));

        let outcome = apply(&mut req, &[AuthMethod::oauth_any()], Some(&validator), None)
            .await
            .unwrap();
        assert!(matches!(outcome, AuthOutcome::Authenticated));

        let user = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, HEADER_USER.as_bytes()))
            .map(|(_, v)| v.clone())
            .expect("X-P2claw-User present");
        assert_eq!(user.as_ref(), b"gh:42");

        let email = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, HEADER_EMAIL.as_bytes()))
            .map(|(_, v)| v.clone())
            .expect("X-P2claw-Email present");
        assert_eq!(email.as_ref(), b"alice@example.com");

        let cookie = req
            .headers
            .iter()
            .find(|(n, _)| eq_ascii_ci(n, b"cookie"))
            .map(|(_, v)| v.clone())
            .expect("cookie header retained for non-session crumbs");
        assert!(
            !std::str::from_utf8(&cookie)
                .unwrap()
                .contains("__p2claw_session"),
            "session cookie must NOT leak to upstream"
        );
        assert!(std::str::from_utf8(&cookie).unwrap().contains("keep=1"));
    }

    #[tokio::test]
    async fn apply_returns_403_style_401_on_aud_mismatch() {
        // JWT minted for a different box (`aud` claim doesn't
        // match ours). Forwarder receives 401 with the
        // P2claw-Auth-Required header — same shape as a missing
        // token. (We deliberately don't surface a 403 separately
        // because the bootstrap treats both as "log in
        // again", and the broker can re-mint with the right `aud`.)
        let sk = SigningKey::generate(&mut OsRng);
        let now = jwt::unix_now();
        let claims = jwt::Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: "different-box".into(),
            sub: "gh:42".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: None,
            picture: None,
            provider: "github".into(),
            iat: now,
            exp: now + 600,
        };
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{h_b64}.{p_b64}.{s_b64}");

        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from(format!("__p2claw_session={token}")),
        ));
        let err = apply(&mut req, &[AuthMethod::oauth_any()], Some(&validator), None)
            .await
            .unwrap_err();
        assert!(matches!(err, MiddlewareError::AuthRequired { .. }));
    }

    /// Per-method `providers` allowlist. JWT carries
    /// `provider: "github"`; the route's `Oauth { providers:
    /// Some(["google"]) }` doesn't accept it, even though sig +
    /// aud + exp all validate. Result: 401 (same shape as any
    /// other rejection), NOT 200.
    #[tokio::test]
    async fn apply_rejects_token_with_unallowed_provider() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = jwt::unix_now();
        let claims = jwt::Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: "this-box".into(),
            sub: "gh:42".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: None,
            picture: None,
            provider: "github".into(),
            iat: now,
            exp: now + 600,
        };
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{h_b64}.{p_b64}.{s_b64}");

        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from(format!("__p2claw_session={token}")),
        ));
        // Route restricts to google; token's `provider` is github.
        let err = apply(
            &mut req,
            &[AuthMethod::oauth_with(vec!["google".into()])],
            Some(&validator),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MiddlewareError::AuthRequired { .. }));
    }

    /// When the JWT's `provider` IS in the allowlist, the
    /// request passes (otherwise-valid token + matching provider).
    #[tokio::test]
    async fn apply_accepts_token_with_allowed_provider() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = jwt::unix_now();
        let claims = jwt::Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: "this-box".into(),
            sub: "gh:42".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: None,
            picture: None,
            provider: "github".into(),
            iat: now,
            exp: now + 600,
        };
        let header = json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{h_b64}.{p_b64}.{s_b64}");

        let cfg = super::super::OAuthConfig {
            broker_url: "https://oauth.p2claw.com".into(),
            expected_aud_z32: "this-box".into(),
        };
        let validator = Arc::new(super::super::OAuthValidator::new(cfg));
        validator
            .jwks()
            .install_for_test(super::super::Jwks {
                keys: vec![super::super::Jwk {
                    kid: "k1".into(),
                    verifying_key: sk.verifying_key(),
                }],
            })
            .await;
        let mut req = empty_request();
        req.headers.push((
            Bytes::from_static(b"Cookie"),
            Bytes::from(format!("__p2claw_session={token}")),
        ));
        // Allowlist includes github + google; github matches.
        let outcome = apply(
            &mut req,
            &[AuthMethod::oauth_with(vec![
                "google".into(),
                "github".into(),
            ])],
            Some(&validator),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, AuthOutcome::Authenticated));
    }
}
