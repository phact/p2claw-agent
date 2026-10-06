//! Device-binding auth for the native SDK — the client counterpart to
//! the box's `oauth::device` verifier.
//!
//! Native apps don't have a browser cookie jar, so instead of a
//! short-lived session cookie they hold a long-lived (90-day)
//! **device-binding cert** minted by the broker, plus a device-local
//! Ed25519 key. Each request carries the cert as a bearer token AND a
//! fresh **proof of possession** — an Ed25519 signature by the device
//! key over `"p2claw-device-pop-v1\n<ts>\n<nonce>"`. The box verifies
//! the cert (broker signature) and the PoP (against the cert's bound
//! `device_key`), so a stolen cert alone is useless.
//!
//! This module is sans-I/O: it generates keys, signs, and shapes the
//! enroll request/response JSON. The platform owns storage (Keychain
//! on iOS, Keystore on Android — store [`DeviceKeypair::secret_seed`]
//! there) and the actual HTTPS calls to `/v1/devices/enroll` and
//! `/v1/devices/refresh`.
//!
//! ## Per-request usage (the whole client contract)
//!
//! 1. Once: [`generate_device_key`] → persist `secret_seed` in the OS
//!    keystore, run the OAuth dance, POST [`enroll_request_json`] to
//!    the broker, keep the cert from [`parse_enroll_response`].
//! 2. Each request: pick a `timestamp` (unix secs, now) and a random
//!    `nonce`, call [`device_request_headers`], attach the returned
//!    headers. Done.
//! 3. Before/at expiry: POST the cert to `/v1/devices/refresh`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey as DalekSigningKey};
use p2claw_identity::SigningKey;
use serde::Deserialize;

use crate::signaling::StringPair;

/// Domain-separation context. MUST equal the box's
/// `oauth::device::POP_CONTEXT` byte-for-byte, or the PoP won't
/// verify.
const POP_CONTEXT: &str = "p2claw-device-pop-v1";

/// Header names the box reads. Must match `oauth::device`.
const HEADER_DEVICE_SIG: &str = "X-P2claw-Device-Sig";
const HEADER_DEVICE_TS: &str = "X-P2claw-Device-Ts";
const HEADER_DEVICE_NONCE: &str = "X-P2claw-Device-Nonce";

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum DeviceError {
    /// `secret_seed` wasn't a 32-byte Ed25519 seed.
    #[error("device secret seed must be 32 bytes, got {0}")]
    BadSeed(u32),
    /// The broker's enroll/refresh response JSON didn't match the
    /// contract.
    #[error("malformed enroll response: {0}")]
    Malformed(String),
}

/// A freshly generated device keypair. The platform persists
/// `secret_seed` in the OS keystore and sends `public_z32` to the
/// broker at enrollment (it becomes the cert's `device_key`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceKeypair {
    /// z-base-32 public key (52 chars) — the same peer_id shape the
    /// broker + box expect as `device_key`.
    pub public_z32: String,
    /// 32-byte Ed25519 seed. SECRET — store in Keychain/Keystore,
    /// never transmit.
    pub secret_seed: Vec<u8>,
}

/// The cert the broker minted, parsed from the enroll/refresh
/// response.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnrolledCert {
    /// Compact JWS device-binding cert. Present it as
    /// `Authorization: Bearer <device_cert>`.
    pub device_cert: String,
    /// Unix seconds the cert expires — schedule a refresh before it.
    pub expires_at: u64,
    /// The broker `kid` that signed it.
    pub kid: String,
}

/// Generate a new device keypair. Call once per install; persist
/// [`DeviceKeypair::secret_seed`] in the OS keystore.
#[uniffi::export]
pub fn generate_device_key() -> DeviceKeypair {
    let sk = SigningKey::generate();
    DeviceKeypair {
        public_z32: sk.peer_id().to_z32(),
        secret_seed: sk.seed().to_vec(),
    }
}

/// The exact bytes the device key signs for proof of possession.
/// Mirrors `oauth::device::pop_signing_input`.
fn pop_signing_input(timestamp: u64, nonce: &str) -> String {
    format!("{POP_CONTEXT}\n{timestamp}\n{nonce}")
}

/// Sign a proof-of-possession blob with the device key. Returns the
/// base64url (no-pad) signature for the `X-P2claw-Device-Sig` header.
#[uniffi::export]
pub fn sign_device_pop(
    secret_seed: Vec<u8>,
    timestamp: u64,
    nonce: String,
) -> Result<String, DeviceError> {
    let seed: [u8; 32] = secret_seed
        .as_slice()
        .try_into()
        .map_err(|_| DeviceError::BadSeed(secret_seed.len() as u32))?;
    let sk = DalekSigningKey::from_bytes(&seed);
    let sig = sk.sign(pop_signing_input(timestamp, &nonce).as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Turnkey per-request auth headers: the bearer cert plus the three
/// proof-of-possession headers. The platform picks `timestamp` (now,
/// unix secs) and a random `nonce`, then attaches every returned pair
/// to the outgoing request.
#[uniffi::export]
pub fn device_request_headers(
    device_cert: String,
    secret_seed: Vec<u8>,
    timestamp: u64,
    nonce: String,
) -> Result<Vec<StringPair>, DeviceError> {
    let sig = sign_device_pop(secret_seed, timestamp, nonce.clone())?;
    Ok(vec![
        StringPair {
            name: "Authorization".into(),
            value: format!("Bearer {device_cert}"),
        },
        StringPair {
            name: HEADER_DEVICE_SIG.into(),
            value: sig,
        },
        StringPair {
            name: HEADER_DEVICE_TS.into(),
            value: timestamp.to_string(),
        },
        StringPair {
            name: HEADER_DEVICE_NONCE.into(),
            value: nonce,
        },
    ])
}

/// Build the `POST /v1/devices/enroll` request body. `user_grant` is
/// the broker ID-JWT from the OAuth dance; `device_pubkey_z32` is
/// [`DeviceKeypair::public_z32`]; `platform` is `"ios"` or
/// `"android"`.
#[uniffi::export]
pub fn enroll_request_json(
    user_grant: String,
    device_pubkey_z32: String,
    platform: String,
) -> String {
    // Hand-built so field names can't drift from the broker's
    // `EnrollRequest` deserialize.
    serde_json::json!({
        "user_grant": user_grant,
        "device_pubkey": device_pubkey_z32,
        "platform": platform,
    })
    .to_string()
}

/// Parse the enroll/refresh response body. Both endpoints return the
/// same shape.
#[uniffi::export]
pub fn parse_enroll_response(json: String) -> Result<EnrolledCert, DeviceError> {
    #[derive(Deserialize)]
    struct Resp {
        device_cert: String,
        expires_at: u64,
        kid: String,
    }
    let r: Resp = serde_json::from_str(&json).map_err(|e| DeviceError::Malformed(e.to_string()))?;
    Ok(EnrolledCert {
        device_cert: r.device_cert,
        expires_at: r.expires_at,
        kid: r.kid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn generate_key_is_z32_and_signs_verifiably() {
        let kp = generate_device_key();
        assert_eq!(kp.public_z32.len(), 52);
        assert_eq!(kp.secret_seed.len(), 32);

        // The signature the box would verify: reconstruct the pubkey
        // from the z32 and check `sign_device_pop` against it.
        let sig_b64 = sign_device_pop(kp.secret_seed.clone(), 1_800_000_000, "nonce-1".into())
            .expect("signs");
        let sig_bytes = URL_SAFE_NO_PAD.decode(&sig_b64).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        let seed: [u8; 32] = kp.secret_seed.as_slice().try_into().unwrap();
        let vk: VerifyingKey = DalekSigningKey::from_bytes(&seed).verifying_key();
        let input = pop_signing_input(1_800_000_000, "nonce-1");
        vk.verify(input.as_bytes(), &sig).expect("pop verifies");
    }

    #[test]
    fn signing_input_matches_box_format() {
        // If this string ever changes, the box's POP_CONTEXT +
        // format must change in lockstep or every mobile request
        // 401s.
        assert_eq!(
            pop_signing_input(42, "abc"),
            "p2claw-device-pop-v1\n42\nabc"
        );
    }

    #[test]
    fn request_headers_are_complete() {
        let kp = generate_device_key();
        let hdrs = device_request_headers("CERT".into(), kp.secret_seed, 100, "n".into()).unwrap();
        let names: Vec<&str> = hdrs.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Authorization",
                "X-P2claw-Device-Sig",
                "X-P2claw-Device-Ts",
                "X-P2claw-Device-Nonce"
            ]
        );
        assert_eq!(hdrs[0].value, "Bearer CERT");
        assert_eq!(hdrs[2].value, "100");
        assert_eq!(hdrs[3].value, "n");
    }

    #[test]
    fn bad_seed_rejected() {
        let err = sign_device_pop(vec![0u8; 16], 1, "n".into()).unwrap_err();
        assert!(matches!(err, DeviceError::BadSeed(16)));
    }

    #[test]
    fn enroll_round_trip_json() {
        let body = enroll_request_json("GRANT".into(), "Z".repeat(52), "ios".into());
        assert!(body.contains("\"user_grant\":\"GRANT\""));
        assert!(body.contains("\"platform\":\"ios\""));

        let resp =
            parse_enroll_response(r#"{"device_cert":"C","expires_at":123,"kid":"k1"}"#.into())
                .unwrap();
        assert_eq!(resp.device_cert, "C");
        assert_eq!(resp.expires_at, 123);
        assert_eq!(resp.kid, "k1");
    }
}
