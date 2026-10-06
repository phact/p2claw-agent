//! Identity-attestation JWT minting.
//!
//! The daemon's auth middleware injects plain `X-P2claw-*` identity
//! headers on every authenticated request. Those headers are forgeable
//! by anyone who can reach the upstream port directly. This module
//! mints a short-lived EdDSA JWT signed with the box's identity key
//! (`crates/identity::SigningKey`) that the upstream can verify against
//! the box's `peer_id` to confirm the headers really came through the
//! daemon.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use p2claw_identity::SigningKey;
use p2claw_translator::ServerRequest;
use serde::Serialize;

use crate::oauth::jwt;

/// Lifetime of an attestation JWT. Authentication-freshness only;
/// the upstream verifier's leeway absorbs ±15s of clock drift.
pub const ATTESTATION_EXP_SECS: u64 = 60;

/// Re-mint when a cached token is within this many seconds of
/// expiry, so the upstream never sees a token about to lapse
/// mid-verification.
const REFRESH_MARGIN_SECS: u64 = 10;

/// Sweep expired cache entries once the map grows past this many
/// identities; bounds growth without a background task.
const CACHE_SWEEP_THRESHOLD: usize = 64;

/// Header name for the attestation token. Distinct from `Authorization`
/// so apps keep their own bearer surface intact.
pub const HEADER_TOKEN: &str = "x-p2claw-identity-token";

/// Header name for the convenience box-id hint. NOT a trust anchor;
/// the upstream's verification key comes from operator config.
pub const HEADER_BOX_ID: &str = "x-p2claw-box-id";

/// JOSE header for the attestation JWS. `alg` is `EdDSA` per RFC 8037;
/// no `kid` — exactly one signing key per box, `iss` carries the
/// peer_id.
#[derive(Serialize)]
struct JoseHeader {
    alg: &'static str,
    typ: &'static str,
}

/// v1 attestation claims. Reserved fields (`aud`, `scope`) are
/// deliberately omitted today — they're for future box-asserted
/// authorization and must not appear in v1 tokens.
#[derive(Serialize)]
struct AttestationClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    iat: u64,
    exp: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,

    auth_method: &'a str,
}

/// Mint a compact-serialization JWS over the v1 claim set, signed
/// with `signer`. `now_secs` is injectable for tests.
pub fn mint(signer: &SigningKey, identity: &jwt::Claims, now_secs: u64) -> String {
    let peer_id = signer.peer_id().to_z32();

    let header = JoseHeader {
        alg: "EdDSA",
        typ: "JWT",
    };
    let header_json = serde_json::to_vec(&header).expect("static JOSE header serializes");
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);

    let claims = AttestationClaims {
        iss: &peer_id,
        sub: identity.sub.as_str(),
        iat: now_secs,
        exp: now_secs + ATTESTATION_EXP_SECS,
        email: Some(identity.email.as_str()),
        name: identity.name.as_deref(),
        auth_method: "oauth",
    };
    let claims_json = serde_json::to_vec(&claims).expect("attestation claims serialize");
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    let mut signing_input = String::with_capacity(header_b64.len() + 1 + claims_b64.len());
    signing_input.push_str(&header_b64);
    signing_input.push('.');
    signing_input.push_str(&claims_b64);

    let signature = signer.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let mut token = signing_input;
    token.push('.');
    token.push_str(&signature_b64);
    token
}

/// Minting is 2 JSON serializations + 3 base64 encodes + an Ed25519
/// sign; with a 60s validity window a request burst from one user
/// would repeat that per request. Cache the minted token per
/// identity (keyed on issuer + the claims that reach the token) and
/// reuse it until [`REFRESH_MARGIN_SECS`] before expiry.
struct CachedToken {
    token: String,
    exp: u64,
}

type TokenCacheKey = (String, String, String, Option<String>);

fn token_cache() -> &'static Mutex<HashMap<TokenCacheKey, CachedToken>> {
    static CACHE: OnceLock<Mutex<HashMap<TokenCacheKey, CachedToken>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached wrapper around [`mint`]. `peer_id` is part of the key so
/// distinct signers (tests, key rotation) never share tokens.
fn mint_cached(
    signer: &SigningKey,
    identity: &jwt::Claims,
    now_secs: u64,
    peer_id: &str,
) -> String {
    let key = (
        peer_id.to_string(),
        identity.sub.clone(),
        identity.email.clone(),
        identity.name.clone(),
    );
    let mut cache = token_cache().lock().expect("token cache lock poisoned");
    if let Some(entry) = cache.get(&key) {
        if now_secs + REFRESH_MARGIN_SECS < entry.exp {
            return entry.token.clone();
        }
    }
    let token = mint(signer, identity, now_secs);
    if cache.len() >= CACHE_SWEEP_THRESHOLD {
        cache.retain(|_, e| now_secs + REFRESH_MARGIN_SECS < e.exp);
    }
    cache.insert(
        key,
        CachedToken {
            token: token.clone(),
            exp: now_secs + ATTESTATION_EXP_SECS,
        },
    );
    token
}

/// Inject the attestation token + box-id convenience header onto a
/// request that has already had its plain `X-P2claw-*` identity
/// headers injected. Idempotent vis-à-vis the prefix strip — both new
/// headers carry the `X-P2claw-` prefix so `strip_identity_headers`
/// removes any forged copies an attacker plants on inbound requests.
pub fn inject(req: &mut ServerRequest, signer: &SigningKey, identity: &jwt::Claims) {
    let now_secs = jwt::unix_now();
    let peer_id = signer.peer_id().to_z32();
    let token = mint_cached(signer, identity, now_secs, &peer_id);

    req.headers.push((
        Bytes::from_static(HEADER_TOKEN.as_bytes()),
        Bytes::from(token),
    ));
    req.headers.push((
        Bytes::from_static(HEADER_BOX_ID.as_bytes()),
        Bytes::from(peer_id),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn signer() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32])
    }

    fn sample_claims() -> jwt::Claims {
        jwt::Claims {
            iss: "https://oauth.p2claw.com/".into(),
            aud: "anything".into(),
            sub: "alice".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: Some("Alice Q.".into()),
            picture: None,
            provider: "google".into(),
            iat: 0,
            exp: 0,
        }
    }

    #[derive(Deserialize)]
    struct MintedClaims {
        iss: String,
        sub: String,
        iat: u64,
        exp: u64,
        email: Option<String>,
        name: Option<String>,
        auth_method: String,
    }

    fn decode_claims(token: &str) -> MintedClaims {
        let claims_b64 = token.split('.').nth(1).expect("compact JWS");
        let claims_json = URL_SAFE_NO_PAD.decode(claims_b64).expect("b64");
        serde_json::from_slice(&claims_json).expect("json")
    }

    #[test]
    fn mint_emits_three_dot_separated_segments() {
        let token = mint(&signer(), &sample_claims(), 1_700_000_000);
        assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn mint_claims_carry_iss_eq_peer_id() {
        let s = signer();
        let token = mint(&s, &sample_claims(), 1_700_000_000);
        let claims = decode_claims(&token);
        assert_eq!(claims.iss, s.peer_id().to_z32());
    }

    #[test]
    fn mint_exp_eq_iat_plus_lifetime() {
        let token = mint(&signer(), &sample_claims(), 1_700_000_000);
        let claims = decode_claims(&token);
        assert_eq!(claims.iat, 1_700_000_000);
        assert_eq!(claims.exp, 1_700_000_000 + ATTESTATION_EXP_SECS);
    }

    #[test]
    fn mint_carries_identity_claims_from_source() {
        let token = mint(&signer(), &sample_claims(), 1_700_000_000);
        let claims = decode_claims(&token);
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Alice Q."));
        assert_eq!(claims.auth_method, "oauth");
    }

    #[test]
    fn mint_signature_verifies_with_box_pubkey() {
        let s = signer();
        let token = mint(&s, &sample_claims(), 1_700_000_000);
        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap();
        let claims_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).expect("b64");
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("ed25519 sig");
        s.verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies against box pubkey");
    }

    #[test]
    fn mint_cached_reuses_until_refresh_margin() {
        let s = signer();
        let peer_id = s.peer_id().to_z32();
        let mut claims = sample_claims();
        claims.sub = "cache-test".into();

        let t0 = mint_cached(&s, &claims, 1_700_000_000, &peer_id);
        // Mid-window: cached token comes back (same iat).
        let t1 = mint_cached(&s, &claims, 1_700_000_030, &peer_id);
        assert_eq!(t0, t1);
        assert_eq!(decode_claims(&t1).iat, 1_700_000_000);
        // Within the refresh margin of expiry: re-minted.
        let t2 = mint_cached(&s, &claims, 1_700_000_055, &peer_id);
        assert_eq!(decode_claims(&t2).iat, 1_700_000_055);
    }

    #[test]
    fn inject_appends_both_headers() {
        let mut req = ServerRequest {
            method: Bytes::from_static(b"GET"),
            path: Bytes::from_static(b"/"),
            headers: Vec::new(),
            body: p2claw_translator::IncomingBody::empty(),
        };
        let s = signer();
        inject(&mut req, &s, &sample_claims());

        let has_token = req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(HEADER_TOKEN.as_bytes()));
        let has_box_id = req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(HEADER_BOX_ID.as_bytes()));
        assert!(has_token, "X-P2claw-Identity-Token injected");
        assert!(has_box_id, "X-P2claw-Box-Id injected");
    }
}
