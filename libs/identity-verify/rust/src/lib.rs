//! Verify p2claw box-attested identity JWTs against a known
//! `peer_id`.
//!
//! Upstream apps behind `p2claw apps expose` receive plain
//! `X-P2claw-User-*` identity headers from the daemon, which a
//! direct connection to the upstream port can forge. The daemon
//! also injects `X-P2claw-Identity-Token` — an EdDSA-JWT signed
//! with the box's identity key whose claims are the same as the
//! plain headers. An app calls [`verify`] with the token, the
//! box's `peer_id` (z-base-32, from operator config), and a
//! `now` timestamp; on success it gets a structured [`Claims`]
//! struct it can trust.
//!
//! # Example
//!
//! ```no_run
//! use p2claw_identity_verify::{verify, VerifyError};
//! use std::time::SystemTime;
//!
//! # fn _example(headers: &p2claw_identity_verify::Headers, trusted_peer_id: &str) -> Result<(), VerifyError> {
//! let claims = verify(headers, trusted_peer_id, SystemTime::now())?;
//! println!("authenticated as {}", claims.sub);
//! # Ok(())
//! # }
//! ```

#![deny(rust_2018_idioms)]

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;

// jsonwebtoken's `decode` returns errors via `kind()`; we map the
// relevant kinds into our flatter `VerifyError`.
//
// `peek_jose_alg` handles the alg-pin defensively so callers see
// the explicit `AlgorithmRejected` variant for forged tokens.

/// Token header name. Matches the daemon-injected header name.
pub const HEADER_TOKEN: &str = "x-p2claw-identity-token";

/// Clock-skew leeway applied to the `exp` check, in seconds.
pub const LEEWAY_SECS: u64 = 15;

/// Caller-supplied header bag. Two-element tuples preserve the
/// duplicate-friendly shape every reasonable HTTP framework's
/// header type already exposes. ASCII / lowercase comparison; the
/// lib normalises.
pub type Headers = [(String, String)];

/// Decoded + verified attestation claims. The same field set the
/// daemon mints (`crates/agent::attestation::AttestationClaims`).
/// `aud` and `scope` are reserved — absent in
/// v1 tokens but parsed when present so a future authz-bearing
/// token decodes without an API change.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub auth_method: Option<String>,

    /// Reserved for future box-asserted authorization. Absent in v1.
    #[serde(default)]
    pub aud: Option<String>,
    /// Reserved for future box-asserted authorization. Absent in v1.
    #[serde(default)]
    pub scope: Option<Vec<String>>,
}

/// Failure shapes for [`verify`]. Flat-ish enum with one struct
/// variant per failure mode.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// No `X-P2claw-Identity-Token` header on the request. App
    /// should treat the request as anonymous.
    #[error("no identity token header on request")]
    TokenMissing,
    /// Token is not a well-formed JWS or claims aren't valid JSON.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// Signature does not validate against `trusted_peer_id`.
    #[error("bad signature")]
    BadSignature,
    /// Token's `exp` is in the past (after leeway).
    #[error("token expired")]
    Expired,
    /// Token's `iat`/`nbf` is in the future (after leeway).
    #[error("token not yet valid")]
    NotYetValid,
    /// Token's `iss` claim doesn't equal the `trusted_peer_id`.
    /// Rare in practice — the box only signs with its own key — but
    /// surfaced explicitly so a misconfiguration (operator pasted
    /// the wrong `peer_id`) doesn't read as "bad signature."
    #[error("token issuer ({token_iss}) does not match trusted peer_id ({trusted})")]
    IssuerMismatch { token_iss: String, trusted: String },
    /// JOSE header carried an `alg` other than `EdDSA`.
    /// Defends against alg-substitution (`alg=none`, `HS256`, etc.).
    #[error("algorithm rejected (expected EdDSA)")]
    AlgorithmRejected,
    /// `trusted_peer_id` failed to decode as a 32-byte Ed25519
    /// public key. Operator-config error, not a token error.
    #[error("invalid peer_id: {0}")]
    BadPeerId(String),
}

/// Verify the attestation token on `headers` against
/// `trusted_peer_id` at `now`.
///
/// `trusted_peer_id` is the operator-configured z-base-32 string
/// the app stores once at setup. NEVER pass a value
/// read from a request header — that's self-certifying garbage.
///
/// On success returns the decoded [`Claims`]. On any failure
/// returns a [`VerifyError`]; the app MUST treat the request as
/// anonymous on any error.
pub fn verify(
    headers: &Headers,
    trusted_peer_id: &str,
    now: SystemTime,
) -> Result<Claims, VerifyError> {
    let token = extract_token(headers).ok_or(VerifyError::TokenMissing)?;
    verify_token(token, trusted_peer_id, now)
}

/// Lower-level entry point: verify a token string directly,
/// without header extraction. Useful for test fixtures + for
/// non-HTTP callers.
pub fn verify_token(
    token: &str,
    trusted_peer_id: &str,
    now: SystemTime,
) -> Result<Claims, VerifyError> {
    // Defence-in-depth alg check BEFORE handing to jsonwebtoken.
    // We can't use `jsonwebtoken::decode_header` here because its
    // `Algorithm` enum rejects unknown algs (including `none`) as a
    // JSON deserialization error, which would mask the actual
    // failure mode. Parse the JOSE header by hand so a forged
    // `alg=none` or `alg=HS256` token returns the explicit
    // `AlgorithmRejected` variant.
    let alg = peek_jose_alg(token)?;
    if alg != "EdDSA" {
        return Err(VerifyError::AlgorithmRejected);
    }

    let pubkey = decode_peer_id(trusted_peer_id)?;
    // `jsonwebtoken::DecodingKey::from_ed_der` despite its name takes
    // the raw 32-byte Ed25519 public key, not an SPKI DER wrapper —
    // it hands the bytes straight to `ring::signature::UnparsedPublicKey`
    // under the `ED25519` algorithm. Verified by inspecting
    // jsonwebtoken 9.x source.
    let decoding_key = DecodingKey::from_ed_der(&pubkey);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = LEEWAY_SECS;
    validation.validate_exp = true;
    // `iss` validation is enforced manually below so the
    // `IssuerMismatch` variant carries both strings for diagnosis.
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("iss".to_string());
    validation.required_spec_claims.insert("sub".to_string());
    validation.required_spec_claims.insert("iat".to_string());

    // jsonwebtoken consults `SystemTime::now()` internally; for
    // deterministic tests we drive its idea of "now" via the
    // validator's `now()` hook is not exposed — we read `exp` from
    // the token + check vs `now` ourselves after decode.
    validation.validate_exp = false;
    let data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind as K;
        match e.kind() {
            K::InvalidSignature => VerifyError::BadSignature,
            K::InvalidAlgorithm | K::InvalidAlgorithmName => VerifyError::AlgorithmRejected,
            K::Json(j) => VerifyError::Malformed(format!("claims json: {j}")),
            K::Base64(b) => VerifyError::Malformed(format!("base64: {b}")),
            K::Crypto(c) => VerifyError::Malformed(format!("crypto: {c}")),
            _ => VerifyError::Malformed(format!("{e}")),
        }
    })?;

    let claims = data.claims;

    if claims.iss != trusted_peer_id {
        return Err(VerifyError::IssuerMismatch {
            token_iss: claims.iss,
            trusted: trusted_peer_id.to_string(),
        });
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerifyError::Malformed("system time before unix epoch".into()))?
        .as_secs();

    if now_secs > claims.exp.saturating_add(LEEWAY_SECS) {
        return Err(VerifyError::Expired);
    }
    if claims.iat > now_secs.saturating_add(LEEWAY_SECS) {
        return Err(VerifyError::NotYetValid);
    }

    Ok(claims)
}

/// Pull the first `X-P2claw-Identity-Token` header value
/// (case-insensitive). HTTP allows multiple identical headers; we
/// pick the first. Duplicates with conflicting values would be
/// suspicious, but the strip-then-inject middleware on the daemon
/// side prevents that arising legitimately, so we don't try to
/// distinguish "duplicated by an attacker" from "duplicated by a
/// transparent proxy" — fail-open to the first value, let
/// signature verification handle the bad case.
fn extract_token(headers: &Headers) -> Option<&str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(HEADER_TOKEN))
        .map(|(_, v)| v.as_str())
}

/// Decode the z-base-32 `peer_id` string into the 32-byte Ed25519
/// public key. Mirrors `p2claw_identity::zbase32::decode` — we
/// don't depend on the identity crate so this micro-lib can be
/// published standalone.
fn decode_peer_id(peer_id_z32: &str) -> Result<[u8; 32], VerifyError> {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let s = peer_id_z32.as_bytes();
    if s.len() != 52 {
        return Err(VerifyError::BadPeerId(format!(
            "expected 52 z-base-32 chars (32 bytes), got {} chars",
            s.len()
        )));
    }

    let mut decode = [0xFFu8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        decode[c as usize] = i as u8;
    }

    let mut out = [0u8; 32];
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out_idx = 0;

    for &ch in s {
        let v = decode[ch as usize];
        if v == 0xFF {
            return Err(VerifyError::BadPeerId(format!(
                "non-alphabet character: 0x{ch:02x}"
            )));
        }
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out_idx >= 32 {
                return Err(VerifyError::BadPeerId("decoded too many bytes".into()));
            }
            out[out_idx] = (buf >> bits) as u8;
            out_idx += 1;
        }
    }
    if out_idx != 32 {
        return Err(VerifyError::BadPeerId(format!(
            "decoded {} bytes, expected 32",
            out_idx
        )));
    }
    // 52 chars × 5 bits = 260 bits = 32 bytes + 4 trailing bits.
    // Per the z-base-32 spec those trailing bits MUST be zero;
    // anything else is a malformed encoding that we reject so two
    // distinct strings can't decode to the same key.
    let trailing_mask = (1u32 << bits) - 1;
    if (buf & trailing_mask) != 0 {
        return Err(VerifyError::BadPeerId("non-zero trailing bits".into()));
    }

    Ok(out)
}

/// Parse the JOSE header's `alg` field without invoking
/// `jsonwebtoken::decode_header` (whose strongly-typed `Algorithm`
/// enum rejects unknown algs as a generic JSON error, masking the
/// alg-substitution attack signal we want to surface).
fn peek_jose_alg(token: &str) -> Result<String, VerifyError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| VerifyError::Malformed("missing JOSE header segment".into()))?;
    if header_b64.is_empty() || token.matches('.').count() != 2 {
        return Err(VerifyError::Malformed(
            "not a compact JWS (expected three dot-separated segments)".into(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .map_err(|e| VerifyError::Malformed(format!("header base64: {e}")))?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| VerifyError::Malformed(format!("header json: {e}")))?;
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::Malformed("JOSE header missing `alg`".into()))?;
    Ok(alg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use std::time::Duration;

    #[derive(Serialize)]
    struct ClaimsOut<'a> {
        iss: &'a str,
        sub: &'a str,
        iat: u64,
        exp: u64,
        email: Option<&'a str>,
        name: Option<&'a str>,
        auth_method: &'a str,
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn peer_id_z32(key: &SigningKey) -> String {
        const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
        let pubkey = key.verifying_key().to_bytes();
        let mut out = String::with_capacity(52);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in &pubkey {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }

    fn mint(
        signer: &SigningKey,
        sub: &str,
        email: Option<&str>,
        iat: u64,
        exp: u64,
        alg: &str,
    ) -> String {
        let header_json = format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let iss = peer_id_z32(signer);
        let claims = ClaimsOut {
            iss: &iss,
            sub,
            iat,
            exp,
            email,
            name: Some("Alice Q."),
            auth_method: "oauth",
        };
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = signer.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn now_at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn roundtrip_minted_token_verifies_and_returns_claims() {
        let s = signer();
        let pid = peer_id_z32(&s);
        let token = mint(
            &s,
            "alice",
            Some("alice@example.com"),
            1_700_000_000,
            1_700_000_060,
            "EdDSA",
        );
        let claims = verify_token(&token, &pid, now_at(1_700_000_030)).expect("verify ok");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.iss, pid);
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.auth_method.as_deref(), Some("oauth"));
    }

    #[test]
    fn rejects_expired_token() {
        let s = signer();
        let token = mint(&s, "alice", None, 1_700_000_000, 1_700_000_060, "EdDSA");
        // `now` is well past `exp + leeway`.
        let err =
            verify_token(&token, &peer_id_z32(&s), now_at(1_700_000_090)).expect_err("must reject");
        assert!(matches!(err, VerifyError::Expired), "got {err:?}");
    }

    #[test]
    fn rejects_alg_none() {
        let s = signer();
        // Hand-construct an `alg=none` token. Signature segment empty.
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims_json = format!(
            r#"{{"iss":"{}","sub":"attacker","iat":1700000000,"exp":1700000060}}"#,
            peer_id_z32(&s)
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let token = format!("{header_b64}.{claims_b64}.");

        let err =
            verify_token(&token, &peer_id_z32(&s), now_at(1_700_000_030)).expect_err("must reject");
        assert!(matches!(err, VerifyError::AlgorithmRejected), "got {err:?}");
    }

    #[test]
    fn rejects_alg_hs256_substitution() {
        let s = signer();
        // HS256 header but no actual MAC; the alg-pin must reject
        // before signature work matters.
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims_json = format!(
            r#"{{"iss":"{}","sub":"attacker","iat":1700000000,"exp":1700000060}}"#,
            peer_id_z32(&s)
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let token = format!("{header_b64}.{claims_b64}.AAAA");

        let err =
            verify_token(&token, &peer_id_z32(&s), now_at(1_700_000_030)).expect_err("must reject");
        assert!(matches!(err, VerifyError::AlgorithmRejected), "got {err:?}");
    }

    #[test]
    fn rejects_wrong_key() {
        let signer_a = SigningKey::from_bytes(&[7u8; 32]);
        let signer_b = SigningKey::from_bytes(&[8u8; 32]);
        let token = mint(
            &signer_a,
            "alice",
            None,
            1_700_000_000,
            1_700_000_060,
            "EdDSA",
        );
        // Tamper iss to match signer_b's peer_id so the
        // iss-mismatch check doesn't short-circuit first — we want
        // to exercise the signature path.
        let parts: Vec<&str> = token.split('.').collect();
        let claims_json = format!(
            r#"{{"iss":"{}","sub":"alice","iat":1700000000,"exp":1700000060,"name":"Alice Q.","auth_method":"oauth"}}"#,
            peer_id_z32(&signer_b)
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        // Re-sign signing_input with signer_a so the signature is
        // valid for signer_a but we'll verify against signer_b.
        let signing_input = format!("{}.{}", parts[0], claims_b64);
        let sig = signer_a.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let tampered = format!("{signing_input}.{sig_b64}");

        let err = verify_token(&tampered, &peer_id_z32(&signer_b), now_at(1_700_000_030))
            .expect_err("must reject");
        assert!(matches!(err, VerifyError::BadSignature), "got {err:?}");
    }

    #[test]
    fn rejects_tampered_claims() {
        let s = signer();
        let pid = peer_id_z32(&s);
        let original = mint(
            &s,
            "alice",
            Some("alice@example.com"),
            1_700_000_000,
            1_700_000_060,
            "EdDSA",
        );
        // Swap claims segment for one with attacker-controlled sub
        // but keep the original signature → signature won't verify.
        let parts: Vec<&str> = original.split('.').collect();
        let evil_claims = format!(
            r#"{{"iss":"{pid}","sub":"admin","iat":1700000000,"exp":1700000060,"email":"admin@example.com","auth_method":"oauth"}}"#
        );
        let evil_b64 = URL_SAFE_NO_PAD.encode(evil_claims.as_bytes());
        let tampered = format!("{}.{}.{}", parts[0], evil_b64, parts[2]);

        let err = verify_token(&tampered, &pid, now_at(1_700_000_030)).expect_err("must reject");
        assert!(matches!(err, VerifyError::BadSignature), "got {err:?}");
    }

    #[test]
    fn rejects_malformed_token() {
        let err = verify_token(
            "not.a.jwt",
            "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            now_at(1_700_000_030),
        )
        .expect_err("must reject");
        assert!(matches!(err, VerifyError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn rejects_issuer_mismatch() {
        // IssuerMismatch fires when the signature verifies but the
        // `iss` claim lies. To exercise it, mint a token signed by
        // key A (so verification against A's peer_id succeeds) but
        // with `iss` pointing at some unrelated peer_id. Verifier
        // configured with A's peer_id → signature OK, iss != trusted
        // → IssuerMismatch.
        let signer_a = SigningKey::from_bytes(&[7u8; 32]);
        let pid_a = peer_id_z32(&signer_a);
        let lying_iss = peer_id_z32(&SigningKey::from_bytes(&[9u8; 32]));

        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims_json = format!(
            r#"{{"iss":"{lying_iss}","sub":"alice","iat":1700000000,"exp":1700000060,"auth_method":"oauth"}}"#
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = signer_a.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let err = verify_token(&token, &pid_a, now_at(1_700_000_030)).expect_err("must reject");
        match err {
            VerifyError::IssuerMismatch { token_iss, trusted } => {
                assert_eq!(token_iss, lying_iss);
                assert_eq!(trusted, pid_a);
            }
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn extract_token_from_headers_case_insensitive() {
        let headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            (
                "X-P2claw-Identity-Token".to_string(),
                "header.payload.sig".to_string(),
            ),
        ];
        assert_eq!(extract_token(&headers), Some("header.payload.sig"));
    }

    #[test]
    fn missing_token_returns_token_missing() {
        let headers: Vec<(String, String)> = vec![("Host".into(), "example.com".into())];
        let err = verify(
            &headers,
            "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            SystemTime::now(),
        )
        .expect_err("must reject");
        assert!(matches!(err, VerifyError::TokenMissing));
    }
}
