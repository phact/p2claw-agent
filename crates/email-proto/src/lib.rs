//! Sealed-mail format shared by the email Worker (which seals) and the
//! agent (which opens).
//!
//! Each admitted message produces two HPKE (RFC 9180, base mode,
//! X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305) ciphertexts
//! sealed to the box's X25519 key:
//!
//! - the **message**: `[u32 BE metadata length][metadata JSON][raw RFC 5322]`;
//! - the **summary**: [`Summary`] as JSON, kept by coord after the message
//!   body expires.
//!
//! Both are laid out as `enc (32 bytes) || ciphertext`, with the message id
//! as AAD so a blob can't be replayed under another id.

#![deny(rust_2018_idioms)]

use hpke::aead::ChaCha20Poly1305;
use hpke::inout::InOutBuf;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};

type Kem = X25519HkdfSha256;

const INFO_MESSAGE: &[u8] = b"p2claw-email/1 message";
const INFO_SUMMARY: &[u8] = b"p2claw-email/1 summary";
/// Bytes of the encapsulated key in front of every sealed blob.
pub const ENC_LEN: usize = 32;
/// Bytes the AEAD tag adds at the end of every sealed blob.
pub const TAG_LEN: usize = 16;

/// What kind of mail a sealed message is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Ordinary admitted mail: goes to the inbox.
    Message,
    /// A Gmail forwarding confirmation: kept apart, owner only.
    ForwardingRequest,
}

/// Admission verdicts the Worker reached, carried to the box.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Auth {
    /// `pass`, `fail`, `none`, …, for the signature that admitted the mail.
    pub dkim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkim_domain: Option<String>,
    /// `pass`, `fail` or `none` (not checked).
    pub arc: String,
}

/// Envelope the Worker seals in front of the raw message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub id: String,
    pub kind: Kind,
    /// Unix seconds.
    pub received_at: u64,
    /// Recipient address, lower-cased.
    pub to: String,
    /// SMTP envelope sender.
    pub envelope_from: String,
    /// `From` address, lower-cased.
    pub from: String,
    /// Gmail account that forwarded the message, when it was forwarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_by: Option<String>,
    pub auth: Auth,
}

/// Kept by coord after the message body expires, so the box can record
/// what it missed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub id: String,
    pub received_at: u64,
    pub from: String,
    #[serde(default)]
    pub subject: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid X25519 key")]
    BadKey,
    #[error("sealed blob is truncated")]
    Truncated,
    #[error("decryption failed")]
    Open,
    #[error("encryption failed")]
    Seal,
    #[error("not enough room in front of the message")]
    NoRoom,
    #[error("malformed metadata: {0}")]
    Metadata(#[from] serde_json::Error),
}

/// Seal `buf[start + ENC_LEN..]` in place: the encapsulated key lands in
/// the `ENC_LEN` placeholder bytes at `start`, the tag is appended, and the
/// blob is `buf[start..]`. Messages can be tens of megabytes, so the
/// plaintext is never copied.
fn seal_in_place(
    public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    buf: &mut Vec<u8>,
    start: usize,
) -> Result<(), Error> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(public).map_err(|_| Error::BadKey)?;
    let (enc, tag) = hpke::single_shot_seal_inout_detached::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        InOutBuf::from(&mut buf[start + ENC_LEN..]),
        aad,
    )
    .map_err(|_| Error::Seal)?;
    buf[start..start + ENC_LEN].copy_from_slice(&enc.to_bytes());
    buf.extend_from_slice(&tag.to_bytes());
    Ok(())
}

fn seal(public: &[u8; 32], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(ENC_LEN + plaintext.len() + TAG_LEN);
    buf.resize(ENC_LEN, 0);
    buf.extend_from_slice(plaintext);
    seal_in_place(public, info, aad, &mut buf, 0)?;
    Ok(buf)
}

fn envelope(meta: &Metadata) -> Result<Vec<u8>, Error> {
    let meta_json = serde_json::to_vec(meta)?;
    let mut out = Vec::with_capacity(4 + meta_json.len());
    out.extend_from_slice(&(meta_json.len() as u32).to_be_bytes());
    out.extend_from_slice(&meta_json);
    Ok(out)
}

/// Seal a message whose raw RFC 5322 bytes already sit at `buf[raw_at..]`,
/// using the `raw_at` bytes in front of them for the envelope; the raw
/// bytes are encrypted in place and the tag appended. Returns the offset of
/// the sealed blob, which runs to the end of `buf`. Fails with
/// [`Error::NoRoom`] if the envelope doesn't fit in front; a few KiB is
/// plenty.
pub fn seal_message_in_place(
    public: &[u8; 32],
    meta: &Metadata,
    buf: &mut Vec<u8>,
    raw_at: usize,
) -> Result<usize, Error> {
    let env = envelope(meta)?;
    let start = raw_at
        .checked_sub(ENC_LEN + env.len())
        .ok_or(Error::NoRoom)?;
    buf[start + ENC_LEN..raw_at].copy_from_slice(&env);
    seal_in_place(public, INFO_MESSAGE, meta.id.as_bytes(), buf, start)?;
    Ok(start)
}

fn open(secret: &[u8; 32], info: &[u8], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < ENC_LEN {
        return Err(Error::Truncated);
    }
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&blob[..ENC_LEN])
        .map_err(|_| Error::Truncated)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        &blob[ENC_LEN..],
        aad,
    )
    .map_err(|_| Error::Open)
}

/// Seal a message (metadata + raw RFC 5322 bytes) to a box's X25519 key.
pub fn seal_message(public: &[u8; 32], meta: &Metadata, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let raw_at = ENC_LEN + envelope(meta)?.len();
    let mut buf = Vec::with_capacity(raw_at + raw.len() + TAG_LEN);
    buf.resize(raw_at, 0);
    buf.extend_from_slice(raw);
    seal_message_in_place(public, meta, &mut buf, raw_at)?;
    Ok(buf)
}

/// Open a sealed message queued under `id`. Returns the metadata and the
/// raw RFC 5322 bytes.
pub fn open_message(
    secret: &[u8; 32],
    id: &str,
    blob: &[u8],
) -> Result<(Metadata, Vec<u8>), Error> {
    let mut plaintext = open(secret, INFO_MESSAGE, id.as_bytes(), blob)?;
    if plaintext.len() < 4 {
        return Err(Error::Truncated);
    }
    let meta_len = u32::from_be_bytes(plaintext[..4].try_into().unwrap()) as usize;
    if plaintext.len() < 4 + meta_len {
        return Err(Error::Truncated);
    }
    let meta: Metadata = serde_json::from_slice(&plaintext[4..4 + meta_len])?;
    plaintext.drain(..4 + meta_len);
    Ok((meta, plaintext))
}

pub fn seal_summary(public: &[u8; 32], summary: &Summary) -> Result<Vec<u8>, Error> {
    seal(
        public,
        INFO_SUMMARY,
        summary.id.as_bytes(),
        &serde_json::to_vec(summary)?,
    )
}

pub fn open_summary(secret: &[u8; 32], id: &str, blob: &[u8]) -> Result<Summary, Error> {
    Ok(serde_json::from_slice(&open(
        secret,
        INFO_SUMMARY,
        id.as_bytes(),
        blob,
    )?)?)
}

/// Generate a fresh X25519 key pair `(secret, public)`. For tests and
/// tooling; boxes derive theirs from the identity key.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let (sk, pk) = Kem::gen_keypair();
    let mut secret = [0u8; 32];
    let mut public = [0u8; 32];
    secret.copy_from_slice(&sk.to_bytes());
    public.copy_from_slice(&pk.to_bytes());
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str) -> Metadata {
        Metadata {
            id: id.into(),
            kind: Kind::Message,
            received_at: 1_790_000_000,
            to: "quiet-river-3847@p2claw.com".into(),
            envelope_from: "you@gmail.com".into(),
            from: "you@gmail.com".into(),
            forwarded_by: None,
            auth: Auth {
                dkim: "pass".into(),
                dkim_domain: Some("gmail.com".into()),
                arc: "none".into(),
            },
        }
    }

    #[test]
    fn message_roundtrip() {
        let (sk, pk) = generate_keypair();
        let raw = b"From: you@gmail.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let blob = seal_message(&pk, &meta("m_1"), raw).unwrap();
        let (m, r) = open_message(&sk, "m_1", &blob).unwrap();
        assert_eq!(m, meta("m_1"));
        assert_eq!(r, raw);
    }

    #[test]
    fn in_place_matches_copying_layout() {
        let (sk, pk) = generate_keypair();
        let raw = vec![b'x'; 100_000];
        let mut buf = vec![0u8; 4096];
        buf.extend_from_slice(&raw);
        let start = seal_message_in_place(&pk, &meta("m_1"), &mut buf, 4096).unwrap();
        assert_eq!(
            buf.len() - start,
            seal_message(&pk, &meta("m_1"), &raw).unwrap().len()
        );
        let (m, r) = open_message(&sk, "m_1", &buf[start..]).unwrap();
        assert_eq!(m, meta("m_1"));
        assert_eq!(r, raw);

        let mut tight = vec![0u8; 8];
        tight.extend_from_slice(b"x");
        assert!(matches!(
            seal_message_in_place(&pk, &meta("m_1"), &mut tight, 8),
            Err(Error::NoRoom)
        ));
    }

    #[test]
    fn wrong_id_fails() {
        let (sk, pk) = generate_keypair();
        let blob = seal_message(&pk, &meta("m_1"), b"x").unwrap();
        assert!(matches!(open_message(&sk, "m_2", &blob), Err(Error::Open)));
    }

    #[test]
    fn summary_roundtrip() {
        let (sk, pk) = generate_keypair();
        let s = Summary {
            id: "m_1".into(),
            received_at: 1,
            from: "you@gmail.com".into(),
            subject: "hi".into(),
        };
        let blob = seal_summary(&pk, &s).unwrap();
        assert_eq!(open_summary(&sk, "m_1", &blob).unwrap(), s);
        assert!(open_message(&sk, "m_1", &blob).is_err());
    }

    #[test]
    fn identity_derived_keys() {
        let key = p2claw_identity::SigningKey::generate();
        let public = p2claw_identity::VerifyingKey::from_peer_id(&key.peer_id())
            .unwrap()
            .x25519_public();
        let blob = seal_message(&public, &meta("m_1"), b"x").unwrap();
        let (_, raw) = open_message(&key.x25519_secret(), "m_1", &blob).unwrap();
        assert_eq!(raw, b"x");
    }
}
