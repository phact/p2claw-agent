//! End-to-end identity-attestation integration.
//!
//! Two contracts:
//!
//! 1. When the OAuth middleware authenticates a request and the
//!    daemon is configured with an identity key, the forwarded
//!    request carries an `X-P2claw-Identity-Token` whose claims
//!    verify against the box's own `peer_id` via the OSS micro-lib
//!    (`p2claw_identity_verify::verify_token`) and match the plain
//!    `X-P2claw-User-*` headers injected alongside.
//!
//! 2. A visitor-supplied inbound `X-P2claw-Identity-Token` is
//!    stripped before authentication runs — same defence-in-depth
//!    the existing prefix strip applies to every `X-P2claw-*`
//!    header. An attacker who reaches the daemon's wire can't
//!    forge attestation either.
//!
//! These tests bypass the upstream-dial path (we observe `apply`'s
//! mutations on the request shell directly), keeping the test
//! self-contained.

use std::sync::Arc;
use std::time::SystemTime;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use p2claw_agent::oauth::middleware::apply;
use p2claw_agent::oauth::{
    jwks::{Jwk, Jwks},
    jwt, OAuthConfig, OAuthValidator,
};
use p2claw_control_proto::AuthMethod;
use p2claw_identity::SigningKey as IdentitySigningKey;
use p2claw_identity_verify::{verify_token, VerifyError};
use p2claw_translator::{IncomingBody, ServerRequest};
use rand::rngs::OsRng;
use serde_json::json;

const ISS: &str = "https://oauth.p2claw.test";
const AUD: &str = "this-box-z32";
const KID: &str = "k1";

fn mint_oauth_jwt(sk: &SigningKey, exp_offset_secs: i64) -> String {
    let now = jwt::unix_now() as i64;
    let exp = (now + exp_offset_secs).max(0) as u64;
    let claims = jwt::Claims {
        iss: ISS.into(),
        aud: AUD.into(),
        sub: "gh:42".into(),
        email: "alice@example.com".into(),
        email_verified: true,
        name: Some("Alice".into()),
        picture: Some("https://avatars/alice".into()),
        provider: "github".into(),
        iat: now as u64,
        exp,
    };
    let header = json!({"alg":"EdDSA","typ":"JWT","kid":KID});
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let sig = sk.sign(format!("{h_b64}.{p_b64}").as_bytes());
    let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{h_b64}.{p_b64}.{s_b64}")
}

async fn build_validator(oauth_sk: &SigningKey) -> Arc<OAuthValidator> {
    let cfg = OAuthConfig {
        broker_url: ISS.into(),
        expected_aud_z32: AUD.into(),
    };
    let validator = Arc::new(OAuthValidator::new(cfg));
    validator
        .jwks()
        .install_for_test(Jwks {
            keys: vec![Jwk {
                kid: KID.into(),
                verifying_key: oauth_sk.verifying_key(),
            }],
        })
        .await;
    validator
}

fn request_with_session_cookie(token: &str) -> ServerRequest {
    ServerRequest {
        method: Bytes::from_static(b"GET"),
        path: Bytes::from_static(b"/probe"),
        headers: vec![
            (
                Bytes::from_static(b"host"),
                Bytes::from_static(b"echo.p2claw.test"),
            ),
            (
                Bytes::from_static(b"Cookie"),
                Bytes::from(format!("__p2claw_session={token}")),
            ),
        ],
        body: IncomingBody::empty(),
    }
}

fn extract_header(req: &ServerRequest, name: &[u8]) -> Option<String> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
}

#[tokio::test]
async fn forwarded_request_carries_attestation_that_verifies_via_micro_lib() {
    let oauth_sk = SigningKey::generate(&mut OsRng);
    let validator = build_validator(&oauth_sk).await;

    // Daemon's identity key — its peer_id is the verify anchor an
    // upstream app would have pasted into config. We use it both
    // sides of this test to prove the round-trip.
    let identity = Arc::new(IdentitySigningKey::generate());
    let box_peer_id = identity.peer_id().to_z32();

    let oauth_token = mint_oauth_jwt(&oauth_sk, 600);
    let mut req = request_with_session_cookie(&oauth_token);

    apply(
        &mut req,
        &[AuthMethod::oauth_any()],
        Some(&validator),
        Some(&identity),
    )
    .await
    .expect("middleware accepts the OAuth session");

    // Plain identity headers (the existing X-P2claw-* injection
    // path) must still be there alongside the new attestation
    // headers.
    let plain_email =
        extract_header(&req, b"x-p2claw-email").expect("plain X-P2claw-Email injected as before");
    assert_eq!(plain_email, "alice@example.com");
    let plain_user = extract_header(&req, b"x-p2claw-user").expect("plain X-P2claw-User injected");
    assert_eq!(plain_user, "gh:42");

    // New attestation surface — the token + the convenience box-id
    // header.
    let attestation_token =
        extract_header(&req, b"x-p2claw-identity-token").expect("X-P2claw-Identity-Token injected");
    let box_id_hint = extract_header(&req, b"x-p2claw-box-id")
        .expect("X-P2claw-Box-Id convenience header injected");
    assert_eq!(
        box_id_hint, box_peer_id,
        "convenience box-id header matches box peer_id"
    );

    // The cross-language gate: verify the daemon's mint via the
    // OSS micro-lib, exactly as a downstream app would. If this
    // passes, the hand-rolled JWS the daemon produces is
    // wire-compatible with `jsonwebtoken` (which is what every
    // language's standard JWT lib parses too).
    let claims = verify_token(&attestation_token, &box_peer_id, SystemTime::now())
        .expect("micro-lib verifies daemon-minted token");

    // Claims are populated from the OAuth claims the middleware just
    // validated.
    assert_eq!(claims.iss, box_peer_id);
    assert_eq!(claims.sub, "gh:42");
    assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
    assert_eq!(claims.name.as_deref(), Some("Alice"));
    assert_eq!(claims.auth_method.as_deref(), Some("oauth"));

    // exp window is 60 seconds after iat.
    assert_eq!(
        claims.exp - claims.iat,
        60,
        "attestation lifetime is the spec-pinned 60s"
    );
}

#[tokio::test]
async fn inbound_attestation_token_is_stripped_before_middleware_decides() {
    // Public route (`auth = []`); apply's first step always strips
    // X-P2claw-* headers regardless of auth posture. An attacker
    // who plants a forged X-P2claw-Identity-Token on their inbound
    // request must not have it survive to the upstream.
    let mut req = ServerRequest {
        method: Bytes::from_static(b"GET"),
        path: Bytes::from_static(b"/"),
        headers: vec![
            (
                Bytes::from_static(b"host"),
                Bytes::from_static(b"echo.p2claw.test"),
            ),
            (
                Bytes::from_static(b"X-P2claw-Identity-Token"),
                Bytes::from_static(b"attacker.forged.token"),
            ),
            (
                Bytes::from_static(b"X-P2claw-Email"),
                Bytes::from_static(b"admin@victim.com"),
            ),
            (
                Bytes::from_static(b"X-P2claw-Box-Id"),
                Bytes::from_static(b"attacker-peer-id"),
            ),
        ],
        body: IncomingBody::empty(),
    };

    apply(&mut req, &[], None, None)
        .await
        .expect("public route runs the strip + returns without auth");

    // All three attacker-controlled X-P2claw-* headers must be
    // gone after the strip; no path inside apply re-injects them
    // on a public route without a valid OAuth session.
    assert!(
        extract_header(&req, b"x-p2claw-identity-token").is_none(),
        "forged identity-token was stripped"
    );
    assert!(
        extract_header(&req, b"x-p2claw-email").is_none(),
        "forged email header was stripped"
    );
    assert!(
        extract_header(&req, b"x-p2claw-box-id").is_none(),
        "forged box-id hint was stripped"
    );
}

#[tokio::test]
async fn micro_lib_rejects_attestation_against_wrong_peer_id() {
    // A token minted by the daemon for box A must NOT verify against
    // box B's peer_id: the trust anchor is load-bearing.
    let oauth_sk = SigningKey::generate(&mut OsRng);
    let validator = build_validator(&oauth_sk).await;
    let identity_a = Arc::new(IdentitySigningKey::generate());
    let identity_b = IdentitySigningKey::generate();

    let oauth_token = mint_oauth_jwt(&oauth_sk, 600);
    let mut req = request_with_session_cookie(&oauth_token);

    apply(
        &mut req,
        &[AuthMethod::oauth_any()],
        Some(&validator),
        Some(&identity_a),
    )
    .await
    .expect("middleware authenticates");

    let attestation_token =
        extract_header(&req, b"x-p2claw-identity-token").expect("token injected");

    // Verify against the WRONG peer_id. Signature is over A's key,
    // verifier expects B's key → BadSignature.
    let err = verify_token(
        &attestation_token,
        &identity_b.peer_id().to_z32(),
        SystemTime::now(),
    )
    .expect_err("verify must reject");
    assert!(
        matches!(err, VerifyError::BadSignature),
        "expected BadSignature, got {err:?}"
    );
}
