//! Device-binding cert validation — the box side of the native
//! mobile SDK auth path.
//!
//! The browser path presents a short-lived session JWT whose `aud`
//! is this box's peer_id (see [`super::jwt`]). Native apps present a
//! long-lived (90-day) **device-binding cert** instead: a broker-
//! signed JWT with `typ="device-binding+jwt"` and the fixed sentinel
//! `aud="p2claw-device-binding"` (multi-box — a device enrolls once
//! and reaches every box, so the cert can't be pinned to one
//! peer_id).
//!
//! Because the cert is a long-lived bearer, the signature alone is
//! not enough: a stolen cert would be full account access. Each
//! request therefore also carries a **proof of possession** — a
//! fresh Ed25519 signature by the device key (whose pubkey the cert
//! binds via the `device_key` claim) over a `{timestamp, nonce}`
//! blob. The box checks:
//!
//! 1. the cert's broker signature (via the JWKS cache, same as the
//!    session path) + `iss` + `aud`-sentinel + `exp`,
//! 2. the PoP signature by `device_key` over the reconstructed blob,
//! 3. the timestamp is within [`POP_WINDOW_SECS`] of now,
//! 4. the nonce hasn't been seen (replay guard).
//!
//! The cert + PoP headers are stripped before the request is
//! forwarded upstream (the PoP headers are `x-p2claw-*`, so the
//! existing spoof-strip removes them; the cert rides `Authorization`,
//! which `strip_credential` removes). Nothing device-auth-related
//! reaches the app — it sees only the injected `X-P2claw-*` identity
//! headers, identical to the browser path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey as BrokerKey};
use p2claw_identity::{PeerId, VerifyingKey as DeviceVerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `typ` header the broker stamps on a device cert. Must match
/// `oauth-broker::claims::DEVICE_BINDING_TYP` byte-for-byte — it's
/// what lets the box refuse a device cert in the session-JWT slot
/// and vice versa, at decode time.
pub const DEVICE_BINDING_TYP: &str = "device-binding+jwt";

/// Fixed `aud` sentinel on a device cert. Must match
/// `oauth-broker::claims::DEVICE_BINDING_AUD`. NOT a peer_id — a
/// device cert is multi-box.
pub const DEVICE_BINDING_AUD: &str = "p2claw-device-binding";

/// PoP header names. All `x-p2claw-*` so the middleware's
/// unconditional identity-strip removes them before the request is
/// forwarded upstream — but the middleware captures them *before*
/// that strip runs.
pub const HEADER_DEVICE_SIG: &str = "x-p2claw-device-sig";
pub const HEADER_DEVICE_TS: &str = "x-p2claw-device-ts";
pub const HEADER_DEVICE_NONCE: &str = "x-p2claw-device-nonce";

/// Domain-separation context for the PoP signing input. Both the box
/// (verifier) and the SDK (signer) build the input as
/// `"{POP_CONTEXT}\n{ts}\n{nonce}"` — byte-identical or the signature
/// won't verify. The `-v1` lets us rotate the scheme without
/// ambiguity.
pub const POP_CONTEXT: &str = "p2claw-device-pop-v1";

/// Max clock skew (either direction) between the PoP timestamp and
/// the box's clock. A PoP older/newer than this is rejected — bounds
/// how long a captured PoP could be replayed if the nonce cache were
/// somehow bypassed (it isn't; this is defense in depth).
pub const POP_WINDOW_SECS: u64 = 60;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceCertError {
    #[error("cert malformed: {0}")]
    Malformed(&'static str),
    #[error("cert header decode: {0}")]
    HeaderDecode(String),
    #[error("cert alg must be EdDSA, got {0}")]
    BadAlgorithm(String),
    #[error("cert typ must be {DEVICE_BINDING_TYP}, got {0:?}")]
    NotDeviceCert(Option<String>),
    #[error("cert missing kid")]
    MissingKid,
    #[error("cert signature invalid")]
    BadSignature,
    #[error("cert payload decode: {0}")]
    PayloadDecode(String),
    #[error("cert issuer mismatch: got {got}, expected {expected}")]
    BadIssuer { got: String, expected: String },
    #[error("cert audience not the device-binding sentinel: {0}")]
    BadAudience(String),
    #[error("cert expired (exp {exp} <= now {now})")]
    Expired { exp: u64, now: u64 },
    #[error("cert email not verified")]
    EmailNotVerified,
    #[error("cert device_key not valid z-base-32 Ed25519")]
    BadDeviceKey,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PopError {
    #[error("missing proof-of-possession headers")]
    Missing,
    #[error("proof-of-possession timestamp not an integer")]
    BadTimestamp,
    #[error("proof-of-possession signature not valid base64")]
    BadSigEncoding,
    #[error("proof-of-possession signature wrong length")]
    BadSigLength,
    #[error(
        "proof-of-possession timestamp outside ±{POP_WINDOW_SECS}s window (ts {ts}, now {now})"
    )]
    OutOfWindow { ts: u64, now: u64 },
    #[error("proof-of-possession signature does not verify against the cert's device_key")]
    BadSignature,
    #[error("proof-of-possession nonce replayed")]
    Replayed,
}

/// The device-cert claims — mirrors
/// `oauth-broker::claims::DeviceBindingClaims`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceClaims {
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
    /// z-base-32 of the Ed25519 pubkey the SDK enrolled. The PoP
    /// signature must verify against this key.
    pub device_key: String,
    pub platform: String,
    pub iat: u64,
    pub exp: u64,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    kid: Option<String>,
}

/// Validate a device-binding cert JWT: broker signature (via
/// `key_lookup`), `iss`, sentinel `aud`, `exp`, `email_verified`, and
/// a usable `device_key`. Returns the claims (including the device
/// pubkey the PoP must match). Does NOT check possession — call
/// [`verify_pop`] with the returned `device_key`.
///
/// Dispatch: `typ` MUST be [`DEVICE_BINDING_TYP`]; a session JWT
/// (`typ="JWT"`) is rejected here so the two paths can't be crossed.
pub fn validate_cert(
    token: &str,
    expected_iss: &str,
    now_unix_secs: impl FnOnce() -> u64,
    key_lookup: impl FnOnce(&str) -> Option<BrokerKey>,
) -> Result<DeviceClaims, DeviceCertError> {
    let mut parts = token.splitn(4, '.');
    let header_b64 = parts
        .next()
        .ok_or(DeviceCertError::Malformed("no header"))?;
    let payload_b64 = parts
        .next()
        .ok_or(DeviceCertError::Malformed("no payload"))?;
    let sig_b64 = parts.next().ok_or(DeviceCertError::Malformed("no sig"))?;
    if parts.next().is_some() {
        return Err(DeviceCertError::Malformed("too many segments"));
    }
    if header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(DeviceCertError::Malformed("empty segment"));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| DeviceCertError::HeaderDecode(e.to_string()))?;
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|e| DeviceCertError::HeaderDecode(e.to_string()))?;

    if header.alg != "EdDSA" {
        return Err(DeviceCertError::BadAlgorithm(header.alg));
    }
    // The custom typ is the guard that keeps a device cert out of
    // the session slot (and vice versa) before any claim check.
    if header.typ.as_deref() != Some(DEVICE_BINDING_TYP) {
        return Err(DeviceCertError::NotDeviceCert(header.typ));
    }
    let kid = header.kid.ok_or(DeviceCertError::MissingKid)?;
    let vk = key_lookup(&kid).ok_or(DeviceCertError::BadSignature)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| DeviceCertError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| DeviceCertError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    let signing_input = format!("{header_b64}.{payload_b64}");
    vk.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| DeviceCertError::BadSignature)?;

    // Signature verified — trust the payload.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DeviceCertError::PayloadDecode(e.to_string()))?;
    let claims: DeviceClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| DeviceCertError::PayloadDecode(e.to_string()))?;

    if claims.iss != expected_iss {
        return Err(DeviceCertError::BadIssuer {
            got: claims.iss.clone(),
            expected: expected_iss.to_string(),
        });
    }
    if claims.aud != DEVICE_BINDING_AUD {
        return Err(DeviceCertError::BadAudience(claims.aud.clone()));
    }
    let now = now_unix_secs();
    if claims.exp <= now {
        return Err(DeviceCertError::Expired {
            exp: claims.exp,
            now,
        });
    }
    if !claims.email_verified {
        return Err(DeviceCertError::EmailNotVerified);
    }
    // Fail early if the device_key can't be parsed — verify_pop
    // would fail anyway, but rejecting here gives a clearer error.
    if parse_device_key(&claims.device_key).is_none() {
        return Err(DeviceCertError::BadDeviceKey);
    }

    Ok(claims)
}

/// Verify a request's proof-of-possession against a cert's
/// `device_key`. `sig_b64`/`ts_str`/`nonce` come from the
/// `X-P2claw-Device-Sig`/`-Ts`/`-Nonce` headers. `now` is the box's
/// clock; `replay` dedupes the nonce.
pub fn verify_pop(
    device_key_z32: &str,
    sig_b64: &str,
    ts_str: &str,
    nonce: &str,
    now: u64,
    replay: &ReplayCache,
) -> Result<(), PopError> {
    let vk = parse_device_key(device_key_z32).ok_or(PopError::BadSignature)?;
    let ts: u64 = ts_str.parse().map_err(|_| PopError::BadTimestamp)?;

    // Window check before the (cheap but not free) signature verify.
    let skew = ts.abs_diff(now);
    if skew > POP_WINDOW_SECS {
        return Err(PopError::OutOfWindow { ts, now });
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(sig_b64))
        .map_err(|_| PopError::BadSigEncoding)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PopError::BadSigLength)?;
    let signature = Signature::from_bytes(&sig_arr);

    let signing_input = pop_signing_input(ts, nonce);
    vk.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| PopError::BadSignature)?;

    // Signature good — burn the nonce. Keep it until the PoP window
    // it belongs to can no longer be replayed.
    if !replay.check_and_insert(nonce, ts + POP_WINDOW_SECS) {
        return Err(PopError::Replayed);
    }
    Ok(())
}

/// The exact bytes the device key signs. Both sides MUST build this
/// identically.
pub fn pop_signing_input(ts: u64, nonce: &str) -> String {
    format!("{POP_CONTEXT}\n{ts}\n{nonce}")
}

fn parse_device_key(z32: &str) -> Option<DeviceVerifyingKey> {
    let pid = PeerId::from_z32(z32).ok()?;
    DeviceVerifyingKey::from_peer_id(&pid).ok()
}

/// Bounded, self-pruning nonce replay guard. A nonce is remembered
/// until its `expiry` (the tail of the PoP window it was minted for);
/// entries are dropped lazily on insert. Global-ish: nonces are
/// random and unique across apps, so one cache per box is correct.
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` (expiring at `expiry`). Returns `true` if it
    /// was fresh, `false` if already present (a replay). Prunes
    /// expired entries opportunistically.
    pub fn check_and_insert(&self, nonce: &str, expiry: u64) -> bool {
        let now = unix_now();
        let mut seen = self.seen.lock().expect("replay cache mutex poisoned");
        // Opportunistic prune — bounded work, keeps the map from
        // growing without a background task.
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(nonce) {
            return false;
        }
        seen.insert(nonce.to_string(), expiry);
        true
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True if `typ` marks a device cert — cheap peek so the middleware
/// can dispatch without a full validate.
pub fn is_device_cert(token: &str) -> bool {
    let Some(header_b64) = token.split('.').next() else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
        return false;
    };
    serde_json::from_slice::<Header>(&bytes)
        .map(|h| h.typ.as_deref() == Some(DEVICE_BINDING_TYP))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey as DalekSigningKey};
    use p2claw_identity::SigningKey;

    const ISS: &str = "https://oauth.p2claw.test";

    /// Mint a device cert the way the broker does: EdDSA over
    /// `header.payload`, `typ=device-binding+jwt`.
    fn mint_cert(
        broker: &DalekSigningKey,
        kid: &str,
        device_key_z32: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA", "typ": DEVICE_BINDING_TYP, "kid": kid
        });
        let claims = serde_json::json!({
            "iss": ISS, "aud": DEVICE_BINDING_AUD, "sub": "github:7",
            "email": "dev@example.com", "email_verified": true,
            "provider": "github", "device_key": device_key_z32,
            "platform": "ios", "iat": iat, "exp": exp,
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = broker.sign(signing_input.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn broker_vk(broker: &DalekSigningKey) -> BrokerKey {
        broker.verifying_key()
    }

    fn device_keypair() -> (DalekSigningKey, String) {
        let sk = SigningKey::generate();
        let z32 = sk.peer_id().to_z32();
        let dalek = DalekSigningKey::from_bytes(&sk.seed());
        (dalek, z32)
    }

    fn sign_pop(device: &DalekSigningKey, ts: u64, nonce: &str) -> String {
        let input = pop_signing_input(ts, nonce);
        URL_SAFE_NO_PAD.encode(device.sign(input.as_bytes()).to_bytes())
    }

    #[test]
    fn cert_and_pop_round_trip() {
        let broker = DalekSigningKey::from_bytes(&SigningKey::generate().seed());
        let (device, dk) = device_keypair();
        let now = 1_800_000_000;
        let cert = mint_cert(&broker, "k1", &dk, now, now + 90 * 86400);

        let claims = validate_cert(
            &cert,
            ISS,
            || now + 10,
            |k| (k == "k1").then(|| broker_vk(&broker)),
        )
        .expect("cert verifies");
        assert_eq!(claims.device_key, dk);
        assert_eq!(claims.sub, "github:7");

        let replay = ReplayCache::new();
        let sig = sign_pop(&device, now, "nonce-abc");
        verify_pop(
            &claims.device_key,
            &sig,
            &now.to_string(),
            "nonce-abc",
            now,
            &replay,
        )
        .expect("pop verifies");
    }

    #[test]
    fn cert_rejects_session_jwt_typ() {
        let broker = DalekSigningKey::from_bytes(&SigningKey::generate().seed());
        // Same broker key + claims but typ=JWT → must be refused.
        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"k1"});
        let (_d, dk) = device_keypair();
        let now = 1_800_000_000u64;
        let claims = serde_json::json!({
            "iss": ISS, "aud": DEVICE_BINDING_AUD, "sub": "github:7",
            "email": "d@e.com", "provider": "github", "device_key": dk,
            "platform": "ios", "iat": now, "exp": now + 100,
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = broker.sign(format!("{h}.{p}").as_bytes());
        let token = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let err = validate_cert(&token, ISS, || now, |_| Some(broker_vk(&broker))).unwrap_err();
        assert!(matches!(err, DeviceCertError::NotDeviceCert(_)));
    }

    #[test]
    fn cert_rejects_wrong_aud_and_expired() {
        let broker = DalekSigningKey::from_bytes(&SigningKey::generate().seed());
        let (_d, dk) = device_keypair();
        let now = 1_800_000_000;
        // Expired.
        let cert = mint_cert(&broker, "k1", &dk, now - 200, now - 1);
        let err = validate_cert(&cert, ISS, || now, |_| Some(broker_vk(&broker))).unwrap_err();
        assert!(matches!(err, DeviceCertError::Expired { .. }));
        // Wrong issuer.
        let cert = mint_cert(&broker, "k1", &dk, now, now + 100);
        let err = validate_cert(
            &cert,
            "https://impostor",
            || now,
            |_| Some(broker_vk(&broker)),
        )
        .unwrap_err();
        assert!(matches!(err, DeviceCertError::BadIssuer { .. }));
    }

    #[test]
    fn pop_rejects_wrong_device_key() {
        let (device, _dk) = device_keypair();
        let (_other, other_dk) = device_keypair();
        let now = 1_800_000_000;
        let replay = ReplayCache::new();
        // Signed by `device`, but verified against `other_dk` → fail.
        let sig = sign_pop(&device, now, "n1");
        let err = verify_pop(&other_dk, &sig, &now.to_string(), "n1", now, &replay).unwrap_err();
        assert_eq!(err, PopError::BadSignature);
    }

    #[test]
    fn pop_rejects_stale_timestamp() {
        let (device, dk) = device_keypair();
        let now = 1_800_000_000;
        let old = now - POP_WINDOW_SECS - 5;
        let replay = ReplayCache::new();
        let sig = sign_pop(&device, old, "n1");
        let err = verify_pop(&dk, &sig, &old.to_string(), "n1", now, &replay).unwrap_err();
        assert!(matches!(err, PopError::OutOfWindow { .. }));
    }

    #[test]
    fn pop_rejects_replayed_nonce() {
        let (device, dk) = device_keypair();
        let now = 1_800_000_000;
        let replay = ReplayCache::new();
        let sig = sign_pop(&device, now, "same-nonce");
        // First use: ok.
        verify_pop(&dk, &sig, &now.to_string(), "same-nonce", now, &replay).unwrap();
        // Replay of the same nonce (even with a fresh valid sig): rejected.
        let sig2 = sign_pop(&device, now, "same-nonce");
        let err = verify_pop(&dk, &sig2, &now.to_string(), "same-nonce", now, &replay).unwrap_err();
        assert_eq!(err, PopError::Replayed);
    }

    #[test]
    fn replay_cache_prunes_expired() {
        let cache = ReplayCache::new();
        // An entry whose expiry is already in the past is pruned on
        // the next insert, so the same nonce can be used again later.
        assert!(cache.check_and_insert("n", 1)); // expiry=1 (long past)
        assert!(cache.check_and_insert("n", u64::MAX)); // pruned, fresh again
        assert!(!cache.check_and_insert("n", u64::MAX)); // now present
    }

    #[test]
    fn pop_signing_input_is_the_pinned_wire_contract() {
        // This exact string is the cross-crate contract with the SDK
        // (`p2claw-mobile::device`). Both sides pin the same literal
        // in a test; if either drifts, its test fails before a real
        // phone ever 401s. Keep in lockstep with
        // `p2claw_mobile::device::tests::signing_input_matches_box_format`.
        assert_eq!(
            pop_signing_input(42, "abc"),
            "p2claw-device-pop-v1\n42\nabc"
        );
        // Header names the SDK sends (canonical case) must match ours
        // (lowercase, matched case-insensitively).
        assert!(HEADER_DEVICE_SIG.eq_ignore_ascii_case("X-P2claw-Device-Sig"));
        assert!(HEADER_DEVICE_TS.eq_ignore_ascii_case("X-P2claw-Device-Ts"));
        assert!(HEADER_DEVICE_NONCE.eq_ignore_ascii_case("X-P2claw-Device-Nonce"));
    }

    #[test]
    fn is_device_cert_peek() {
        let broker = DalekSigningKey::from_bytes(&SigningKey::generate().seed());
        let (_d, dk) = device_keypair();
        let cert = mint_cert(&broker, "k1", &dk, 100, 200);
        assert!(is_device_cert(&cert));
        // A session-JWT header peeks as false.
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"k"}"#);
        assert!(!is_device_cert(&format!("{h}.x.y")));
    }
}
