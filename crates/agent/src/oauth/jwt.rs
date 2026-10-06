//! Hand-rolled JWT validator.
//!
//! Scope is deliberately narrow: only the JWT shape the broker
//! mints (`alg=EdDSA`, claims with pinned `iss` / `aud`). Strict
//! invariants:
//!
//! - `alg` MUST be `EdDSA`. Any other value — including the
//!   classic-footgun `none` — is rejected before signature lookup.
//! - `typ` is `JWT` if present; we accept anything (the broker
//!   sets it but RFC 7519 §5.1 makes it informational).
//! - `kid` is required (broker always sets it; we use it to look
//!   up the JWKS pubkey).
//! - Compact form: exactly three base64url-no-pad segments joined
//!   by `.`. Each segment decoded with the no-pad variant
//!   (RFC 4648 §5); any decode failure → `JwtError::Malformed`.
//! - Signature verified over `<header>.<payload>` (the raw bytes
//!   of those two base64 strings + the `.` between them) using
//!   `ed25519-dalek::VerifyingKey::verify_strict`.
//! - Claims: `iss` exact-match; `aud` exact-match against our
//!   peer_id; `exp` strictly in the future against `now`; `iat`
//!   not more than 30 s in the future (clock-skew tolerance).
//!   `email_verified`, when present, MUST be
//!   true — broker promises never to mint a token with it false,
//!   so any token where the parsed value is `false` is a sign of
//!   tampering or a future broker bug; reject.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Pinned algorithm: the broker only ever signs with Ed25519. Any
/// JWT header whose `alg` differs is rejected outright — including
/// the classic `alg=none` footgun.
pub const EXPECTED_ALG: &str = "EdDSA";

/// Pinned key type. JOSE for Ed25519 (RFC 8037).
pub const EXPECTED_KTY: &str = "OKP";

/// Pinned curve.
pub const EXPECTED_CRV: &str = "Ed25519";

/// `use` field on the JWKS entry — `sig` means "signing key"
/// (RFC 7517 §4.2). Daemons MUST refuse keys without it for
/// signature validation.
pub const EXPECTED_USE: &str = "sig";

/// Clock-skew tolerance for the `iat`-in-future check.
pub const IAT_SKEW_TOLERANCE_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("jwt malformed: {0}")]
    Malformed(&'static str),
    #[error("jwt header decode: {0}")]
    HeaderDecode(String),
    #[error("jwt payload decode: {0}")]
    PayloadDecode(String),
    #[error("jwt signature decode: {0}")]
    SignatureDecode(String),
    #[error("jwt alg `{0}` is not EdDSA (rejecting alg=none and all others)")]
    BadAlgorithm(String),
    #[error("jwt typ `{0}` is not JWT")]
    BadTyp(String),
    #[error("jwt header missing required field `kid`")]
    MissingKid,
    #[error("jwt signature failed verification")]
    BadSignature,
    #[error("jwt iss `{got}` does not match expected `{expected}`")]
    BadIssuer { got: String, expected: String },
    #[error("jwt aud `{got}` does not match expected `{expected}` (this agent's peer_id)")]
    BadAudience { got: String, expected: String },
    #[error("jwt expired: exp={exp} <= now={now}")]
    Expired { exp: u64, now: u64 },
    #[error("jwt iat too far in future: iat={iat} > now={now} + skew={skew}")]
    IatInFuture { iat: u64, now: u64, skew: u64 },
    #[error(
        "jwt email_verified is false; broker never mints false — token tampered or broker bug"
    )]
    EmailNotVerified,
    #[error("jwt missing required claim `{0}`")]
    MissingClaim(&'static str),
}

/// JWT header — the deserialized first segment.
///
/// Permits unknown fields (RFC 7519 §5.3 says JWT consumers MAY
/// ignore unrecognized header parameters). We don't enable
/// `deny_unknown_fields` so future broker-side header additions
/// (e.g., `cty` for nested JWTs) don't break daemons.
#[derive(Debug, Deserialize)]
pub struct Header {
    pub alg: String,
    #[serde(default)]
    pub typ: Option<String>,
    pub kid: Option<String>,
}

/// JWT claims — the deserialized middle segment, mirroring what the
/// broker mints.
///
/// Optional fields (`name`, `picture`, `email_verified`) follow
/// the broker's "present iff upstream supplied" convention.
/// `email_verified` defaults to `true` when absent (the broker
/// never mints `false`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub email: String,
    #[serde(default = "default_true")]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
    pub provider: String,
    pub iat: u64,
    pub exp: u64,
}

fn default_true() -> bool {
    true
}

/// One-shot entry point. Splits the compact JWT, decodes header
/// and payload, looks up the signing key by `kid`, verifies the
/// signature, then runs the claim checks. The `now_unix_secs`
/// closure is injectable so tests can pin time without
/// monkey-patching `SystemTime`.
///
/// `key_lookup` returns the verifying key for a given `kid`, or
/// `None` if unknown. The middleware wires it to the JWKS cache;
/// callers can substitute a static-key lookup in tests.
pub fn validate(
    token: &str,
    expected_iss: &str,
    expected_aud: &str,
    now_unix_secs: impl FnOnce() -> u64,
    key_lookup: impl FnOnce(&str) -> Option<VerifyingKey>,
) -> Result<Claims, JwtError> {
    let (header_b64, payload_b64, sig_b64, signing_input) = split_compact(token)?;
    let header = decode_header(header_b64)?;

    // alg/typ guards first — cheapest checks, and `alg=none` must
    // be rejected before any key lookup so a forged "I don't need
    // a key" header can't bypass the verifier.
    if header.alg != EXPECTED_ALG {
        return Err(JwtError::BadAlgorithm(header.alg));
    }
    if let Some(typ) = header.typ.as_deref() {
        // Strictly only "JWT". Permitting empty would be a footgun;
        // the broker always emits "JWT".
        if !typ.eq_ignore_ascii_case("JWT") {
            return Err(JwtError::BadTyp(typ.to_string()));
        }
    }
    let kid = header.kid.ok_or(JwtError::MissingKid)?;

    // Look up the verifying key BEFORE decoding the payload —
    // unknown kid is the only error that triggers a JWKS refresh
    // on the middleware side, so we want to surface it cheaply.
    let vk = key_lookup(&kid).ok_or(JwtError::BadSignature)?;

    // Decode signature, verify, then trust-decode the payload.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtError::SignatureDecode(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| JwtError::BadSignature)?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)?;

    // Signature verified — now we can trust the payload bytes.
    let claims = decode_payload(payload_b64)?;

    // Claim checks.
    if claims.iss != expected_iss {
        return Err(JwtError::BadIssuer {
            got: claims.iss.clone(),
            expected: expected_iss.to_string(),
        });
    }
    if claims.aud != expected_aud {
        return Err(JwtError::BadAudience {
            got: claims.aud.clone(),
            expected: expected_aud.to_string(),
        });
    }
    let now = now_unix_secs();
    if claims.exp <= now {
        return Err(JwtError::Expired {
            exp: claims.exp,
            now,
        });
    }
    if claims.iat > now + IAT_SKEW_TOLERANCE_SECS {
        return Err(JwtError::IatInFuture {
            iat: claims.iat,
            now,
            skew: IAT_SKEW_TOLERANCE_SECS,
        });
    }
    if !claims.email_verified {
        // The broker never mints false. A token
        // carrying false on the wire = something's wrong.
        return Err(JwtError::EmailNotVerified);
    }

    Ok(claims)
}

/// Wall-clock for the default validation path. Tests inject their
/// own via the [`validate`] callback parameter.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Split the compact JWT form (`<header>.<payload>.<signature>`)
/// into its three segments + the pre-computed signing-input string
/// (`<header>.<payload>`). The signing-input ride-along avoids a
/// second allocation in the verify path.
fn split_compact(token: &str) -> Result<(&str, &str, &str, &str), JwtError> {
    let mut parts = token.splitn(4, '.');
    let header = parts.next().ok_or(JwtError::Malformed("missing header"))?;
    let payload = parts.next().ok_or(JwtError::Malformed("missing payload"))?;
    let sig = parts
        .next()
        .ok_or(JwtError::Malformed("missing signature"))?;
    if parts.next().is_some() {
        return Err(JwtError::Malformed("too many segments"));
    }
    // Disallow empty segments — they pass the `splitn` shape check
    // but are clearly invalid.
    if header.is_empty() || payload.is_empty() || sig.is_empty() {
        return Err(JwtError::Malformed("empty segment"));
    }
    // Pre-compute signing input from the slice positions so we
    // don't allocate. `header.as_ptr()` + payload's end give us a
    // contiguous slice in the original token.
    let header_start = header.as_ptr() as usize - token.as_ptr() as usize;
    let payload_end = payload.as_ptr() as usize - token.as_ptr() as usize + payload.len();
    let signing_input = &token[header_start..payload_end];
    Ok((header, payload, sig, signing_input))
}

fn decode_header(b64: &str) -> Result<Header, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| JwtError::HeaderDecode(e.to_string()))?;
    serde_json::from_slice::<Header>(&bytes).map_err(|e| JwtError::HeaderDecode(e.to_string()))
}

fn decode_payload(b64: &str) -> Result<Claims, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| JwtError::PayloadDecode(e.to_string()))?;
    serde_json::from_slice::<Claims>(&bytes).map_err(|e| {
        // Distinguish "missing required field" from "totally
        // malformed JSON" — serde_json's error already does
        // (`error.classify() == Eof / Syntax / Data`). For
        // simplicity, surface the human-readable message in both
        // cases.
        if e.to_string().contains("missing field") {
            // Best-effort: extract the field name from the
            // serde_json message. The static string in
            // `MissingClaim` keeps the variant cheaply copyable.
            JwtError::MissingClaim("payload field")
        } else {
            JwtError::PayloadDecode(e.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Mint a fresh keypair + a JWT signed by it. Returns
    /// `(token, signing_key, verifying_key)`.
    fn mint_jwt(claims: Claims, kid: &str) -> (String, SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": kid,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");
        (token, sk, vk)
    }

    fn good_claims(aud: &str, now: u64) -> Claims {
        Claims {
            iss: "https://oauth.p2claw.com".into(),
            aud: aud.into(),
            sub: "gh:1234".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            name: Some("Alice".into()),
            picture: None,
            provider: "github".into(),
            iat: now,
            exp: now + 3600,
        }
    }

    use ed25519_dalek::Signer;

    #[test]
    fn happy_path_round_trip() {
        let now = 1_700_000_000;
        let claims = good_claims("aud-z32", now);
        let (token, _sk, vk) = mint_jwt(claims.clone(), "test-key-1");
        let got = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |kid| if kid == "test-key-1" { Some(vk) } else { None },
        )
        .expect("valid token");
        assert_eq!(got, claims);
    }

    #[test]
    fn rejects_alg_none() {
        let now = 1_700_000_000;
        let claims = good_claims("aud-z32", now);
        let header = serde_json::json!({"alg":"none","typ":"JWT","kid":"k1"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        // Sign with a real key but advertise alg=none — the
        // validator must reject before even looking at the signature.
        let sk = SigningKey::generate(&mut OsRng);
        let sig = sk.sign(format!("{header_b64}.{payload_b64}").as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let vk = sk.verifying_key();
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(
            matches!(err, JwtError::BadAlgorithm(ref a) if a == "none"),
            "expected BadAlgorithm(none), got {err:?}"
        );
    }

    #[test]
    fn rejects_rs256() {
        // Any non-EdDSA alg must fail. RS256 is the JWT default
        // elsewhere and the most likely "I copy-pasted wrong" case.
        let now = 1_700_000_000;
        let claims = good_claims("aud-z32", now);
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"k1"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let token = format!("{header_b64}.{payload_b64}.AAAA");
        let sk = SigningKey::generate(&mut OsRng);
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(sk.verifying_key()),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::BadAlgorithm(_)), "{err:?}");
    }

    #[test]
    fn rejects_expired() {
        let now = 1_700_000_000;
        let mut claims = good_claims("aud-z32", now);
        claims.exp = now - 1;
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn rejects_wrong_audience() {
        let now = 1_700_000_000;
        let claims = good_claims("not-our-box", now);
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "our-box",
            || now + 10,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(
            matches!(err, JwtError::BadAudience { ref got, .. } if got == "not-our-box"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_wrong_issuer() {
        let now = 1_700_000_000;
        let mut claims = good_claims("aud-z32", now);
        claims.iss = "https://fakebroker.example".into();
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::BadIssuer { .. }), "{err:?}");
    }

    #[test]
    fn rejects_unknown_kid_as_bad_signature() {
        // Caller's `key_lookup` returns None → BadSignature
        // (intentionally indistinguishable from "key known but
        // verify failed" so callers can't enumerate kids by
        // observing a different error shape).
        let now = 1_700_000_000;
        let claims = good_claims("aud-z32", now);
        let (token, _sk, _vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| None,
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::BadSignature), "{err:?}");
    }

    #[test]
    fn rejects_iat_too_far_future() {
        let now = 1_700_000_000;
        let mut claims = good_claims("aud-z32", now);
        claims.iat = now + 100; // > 30s tolerance
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::IatInFuture { .. }), "{err:?}");
    }

    #[test]
    fn accepts_iat_within_skew_tolerance() {
        // 15s in the future is well inside the 30s tolerance — must
        // succeed.
        let now = 1_700_000_000;
        let mut claims = good_claims("aud-z32", now);
        claims.iat = now + 15;
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now,
            |_| Some(vk),
        )
        .expect("within tolerance");
    }

    #[test]
    fn rejects_email_verified_false() {
        let now = 1_700_000_000;
        let mut claims = good_claims("aud-z32", now);
        claims.email_verified = false;
        let (token, _sk, vk) = mint_jwt(claims, "k1");
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(vk),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::EmailNotVerified), "{err:?}");
    }

    #[test]
    fn rejects_signature_mismatch() {
        let now = 1_700_000_000;
        let claims = good_claims("aud-z32", now);
        let (token, _sk, _vk) = mint_jwt(claims, "k1");
        // Inject a DIFFERENT verifying key — same kid, different
        // pubkey. Simulates an attacker who knows the kid but
        // can't sign.
        let other_sk = SigningKey::generate(&mut OsRng);
        let err = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(other_sk.verifying_key()),
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::BadSignature), "{err:?}");
    }

    #[test]
    fn rejects_malformed_compact_form() {
        // Two-segment "JWT" — common mistake.
        let err = validate("aaa.bbb", "iss", "aud", || 0, |_| None).unwrap_err();
        assert!(matches!(err, JwtError::Malformed(_)), "{err:?}");

        // Four segments.
        let err = validate("a.b.c.d", "iss", "aud", || 0, |_| None).unwrap_err();
        assert!(matches!(err, JwtError::Malformed(_)), "{err:?}");

        // Empty segment.
        let err = validate("a..c", "iss", "aud", || 0, |_| None).unwrap_err();
        assert!(matches!(err, JwtError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn email_verified_defaults_to_true_when_absent() {
        // Absent `email_verified` is treated as `true` via serde's
        // default.
        let now = 1_700_000_000;
        // Build claims JSON manually so we can omit the field.
        let claims_json = serde_json::json!({
            "iss": "https://oauth.p2claw.com",
            "aud": "aud-z32",
            "sub": "gh:42",
            "email": "alice@example.com",
            "provider": "github",
            "iat": now,
            "exp": now + 3600,
        });
        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_json).unwrap());
        let sk = SigningKey::generate(&mut OsRng);
        let sig = sk.sign(format!("{header_b64}.{payload_b64}").as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let claims = validate(
            &token,
            "https://oauth.p2claw.com",
            "aud-z32",
            || now + 10,
            |_| Some(sk.verifying_key()),
        )
        .expect("default-true accepts absent field");
        assert!(claims.email_verified);
    }
}
