//! Regenerate `libs/identity-verify/test-vectors.json`, the
//! cross-language fixture every verify-library binding pins against.
//!
//! Lives in the agent crate so the signature-bearing cases are minted by
//! the daemon's real `attestation::mint` path; the forged-shape cases
//! are hand-constructed because the daemon never emits them.
//!
//! Re-run after any change to `attestation.rs`'s JWS encoding and
//! commit the regenerated JSON:
//!
//! ```text
//! cargo run -p p2claw-agent --bin gen-identity-vectors [OUT_PATH]
//! ```
//!
//! `OUT_PATH` defaults to `libs/identity-verify/test-vectors.json`
//! relative to the workspace root. Inputs are deterministic (fixed
//! Ed25519 seeds, fixed iat/exp), so the output is reproducible.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p2claw_agent::attestation;
use p2claw_agent::oauth::jwt;
use p2claw_identity::SigningKey;
use std::path::PathBuf;

// Two fixed Ed25519 seeds. The `negative_wrong_key` and
// `negative_issuer_mismatch` cases mint with seed B; everything
// else with seed A; positive verification uses seed A's peer_id.
const SEED_A: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const SEED_B: [u8; 32] = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
];

const IAT: u64 = 1_700_000_000;
const VERIFY_AT_FRESH: u64 = IAT + 30; // mid-window for positive cases
const VERIFY_AT_PAST_EXP: u64 = IAT + attestation::ATTESTATION_EXP_SECS + 30; // past exp + leeway

/// Future iat used by `negative_not_yet_valid`: more than the 15s
/// verifier leeway ahead of `verify_at`, so it must reject.
const IAT_FUTURE: u64 = VERIFY_AT_FRESH + 60;

fn sample_identity() -> jwt::Claims {
    jwt::Claims {
        iss: "https://oauth.p2claw.com/".into(),
        aud: "anything".into(),
        sub: "alice@example.com".into(),
        email: "alice@example.com".into(),
        email_verified: true,
        name: Some("Alice Q.".into()),
        picture: None,
        provider: "google".into(),
        iat: 0,
        exp: 0,
    }
}

/// Hand-construct a JWS for the cases the daemon would never
/// emit. `signer` is None for `alg=none` (signature segment
/// empty); when Some, signs the input.
fn hand_construct(
    header_json: &[u8],
    claims_json: &[u8],
    signer: Option<&SigningKey>,
    signature_override: Option<&str>,
) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig_b64 = if let Some(s) = signature_override {
        s.to_string()
    } else if let Some(signer) = signer {
        let sig = signer.sign(signing_input.as_bytes());
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    } else {
        String::new()
    };
    format!("{signing_input}.{sig_b64}")
}

fn main() {
    let signer_a = SigningKey::from_seed(&SEED_A);
    let signer_b = SigningKey::from_seed(&SEED_B);
    let pid_a = signer_a.peer_id().to_z32();
    let pid_b = signer_b.peer_id().to_z32();
    let identity = sample_identity();

    // -------- positive: real daemon mint, signed by A, iss=A --------
    let positive_token = attestation::mint(&signer_a, &identity, IAT);

    // -------- negative_expired: same valid token, past exp ------------
    let expired_token = positive_token.clone();

    // -------- negative_wrong_key: real daemon mint, signed by B, iss=B
    // Verify against A's peer_id ⇒ signature path fails (issuer also
    // mismatches but signature is checked first in the verify pipeline).
    let wrong_key_token = attestation::mint(&signer_b, &identity, IAT);

    // -------- negative_not_yet_valid: real daemon mint, future iat -----
    // A box whose clock runs far ahead could emit this; 60s is past
    // the 15s leeway so it must reject.
    let not_yet_valid_token = attestation::mint(&signer_a, &identity, IAT_FUTURE);

    // -------- negative_tampered: positive + swap claims segment --------
    let parts: Vec<&str> = positive_token.split('.').collect();
    let evil_claims = format!(
        r#"{{"iss":"{pid_a}","sub":"admin@example.com","iat":{IAT},"exp":{exp},"email":"admin@example.com","name":"Alice Q.","auth_method":"oauth"}}"#,
        exp = IAT + attestation::ATTESTATION_EXP_SECS,
    );
    let evil_b64 = URL_SAFE_NO_PAD.encode(evil_claims.as_bytes());
    let tampered_token = format!("{}.{}.{}", parts[0], evil_b64, parts[2]);

    // -------- negative_alg_none: forged, daemon would never emit -------
    let alg_none_claims = format!(
        r#"{{"iss":"{pid_a}","sub":"attacker","iat":{IAT},"exp":{exp}}}"#,
        exp = IAT + attestation::ATTESTATION_EXP_SECS,
    );
    let alg_none_token = hand_construct(
        br#"{"alg":"none","typ":"JWT"}"#,
        alg_none_claims.as_bytes(),
        None,
        Some(""),
    );

    // -------- negative_alg_hs256: alg-substitution attempt -------------
    let alg_hs256_token = hand_construct(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        alg_none_claims.as_bytes(),
        None,
        Some("AAAAAAAAAAAAAAAAAAAAAAAA"),
    );

    // -------- negative_malformed: not a JWT at all ---------------------
    let malformed_token = "not.a.jwt".to_string();

    // -------- negative_issuer_mismatch: signed by A but iss=B ----------
    // Signature verifies (correctly signed by A), but the `iss`
    // claim points at B. Verifier configured with A's peer_id sees
    // sig OK but iss mismatch → distinct error variant for the
    // operator-pasted-wrong-peer_id diagnostic case.
    let lying_claims = format!(
        r#"{{"iss":"{pid_b}","sub":"alice@example.com","iat":{IAT},"exp":{exp},"email":"alice@example.com","name":"Alice Q.","auth_method":"oauth"}}"#,
        exp = IAT + attestation::ATTESTATION_EXP_SECS,
    );
    let issuer_mismatch_token = hand_construct(
        br#"{"alg":"EdDSA","typ":"JWT"}"#,
        lying_claims.as_bytes(),
        Some(&signer_a),
        None,
    );

    let exp = IAT + attestation::ATTESTATION_EXP_SECS;
    let vectors = serde_json::json!({
        "spec_version": "0.1",
        "generated_by": "cargo run -p p2claw-agent --bin gen-identity-vectors",
        "note": "Signature-bearing cases are minted by the daemon's actual `attestation::mint` (single source of truth for the wire format). Forged-shape cases (alg_none, alg_hs256, malformed, issuer_mismatch) are hand-constructed since the daemon would never emit them. All inputs deterministic: fixed Ed25519 seeds + fixed iat/exp. Verify-side tests pass `verify_at` as the `now` argument so the fixture never wall-clock-expires.",
        "trusted_peer_id": pid_a,
        "leeway_secs": 15,
        "cases": [
            {
                "name": "positive_oauth_identity",
                "description": "Valid token issued by trusted peer_id with full OAuth identity claims (daemon mint)",
                "token": positive_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "ok",
                "expected_claims": {
                    "iss": pid_a,
                    "sub": "alice@example.com",
                    "iat": IAT,
                    "exp": exp,
                    "email": "alice@example.com",
                    "name": "Alice Q.",
                    "auth_method": "oauth"
                }
            },
            {
                "name": "negative_expired",
                "description": "Same valid token, but verify_at is past exp + leeway",
                "token": expired_token,
                "verify_at": VERIFY_AT_PAST_EXP,
                "expect": "err:Expired"
            },
            {
                "name": "negative_alg_none",
                "description": "Forged token with alg=none header — must reject without verifying",
                "token": alg_none_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:AlgorithmRejected"
            },
            {
                "name": "negative_alg_hs256",
                "description": "Alg-substitution attempt with alg=HS256 — must reject (pinned to EdDSA)",
                "token": alg_hs256_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:AlgorithmRejected"
            },
            {
                "name": "negative_wrong_key",
                "description": "Daemon mint by signer B (iss=B); verified against signer A's peer_id ⇒ signature path rejection",
                "token": wrong_key_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:BadSignature"
            },
            {
                "name": "negative_tampered",
                "description": "Positive token with claims segment swapped — signature no longer matches",
                "token": tampered_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:BadSignature"
            },
            {
                "name": "negative_malformed",
                "description": "Not a JWT — JOSE header decode fails",
                "token": malformed_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:Malformed"
            },
            {
                "name": "negative_not_yet_valid",
                "description": "Daemon mint with iat far in the future — verify_at < iat - leeway ⇒ NotYetValid",
                "token": not_yet_valid_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:NotYetValid"
            },
            {
                "name": "negative_issuer_mismatch",
                "description": "Signed by A but iss=B's peer_id; verifier configured with A's peer_id ⇒ sig OK but iss mismatch",
                "token": issuer_mismatch_token,
                "verify_at": VERIFY_AT_FRESH,
                "expect": "err:IssuerMismatch"
            }
        ]
    });

    let out_path = match std::env::args_os().nth(1) {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/agent has ../../ ancestors")
            .join("libs/identity-verify/test-vectors.json"),
    };

    let pretty = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    std::fs::write(&out_path, pretty + "\n").expect("write vectors");
    println!("wrote {}", out_path.display());
}
