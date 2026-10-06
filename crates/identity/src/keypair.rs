use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::Signer as _;
use ed25519_dalek::Verifier as _;

use crate::error::IdentityError;
use crate::peer_id::PeerId;

/// Raw Ed25519 seed (32 bytes). Keep out of logs.
pub type SecretKey = [u8; 32];

/// Ed25519 signing key. Wraps `ed25519_dalek::SigningKey` with
/// p2claw-flavoured conveniences: `PeerId` derivation, on-disk
/// persistence with `0600` permissions, and a seed-based
/// constructor.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately does not print the seed.
        write!(f, "SigningKey(peer_id={})", self.peer_id())
    }
}

impl SigningKey {
    /// Generate a fresh keypair from the OS RNG.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self(ed25519_dalek::SigningKey::generate(&mut csprng))
    }

    /// Construct from an existing 32-byte seed.
    pub fn from_seed(seed: &SecretKey) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Expose the raw seed. Callers must not log this.
    pub fn seed(&self) -> SecretKey {
        self.0.to_bytes()
    }

    /// Derive the `PeerId`.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(self.0.verifying_key().to_bytes())
    }

    /// Verifying-key view (for handing to signature verifiers).
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.0.sign(message)
    }

    /// X25519 private key derived from this Ed25519 key, for HPKE.
    /// Pairs with [`VerifyingKey::x25519_public`]. Unclamped; X25519
    /// clamps on use. Callers must not log this.
    pub fn x25519_secret(&self) -> [u8; 32] {
        self.0.to_scalar_bytes()
    }

    /// Load a key from disk. Errors if the file does not exist, is not
    /// exactly 32 bytes, or any other IO failure.
    ///
    /// Unlike [`load_or_generate`](Self::load_or_generate) this method
    /// never generates a fresh key. Used for the coord root key, where
    /// silent auto-generation would be catastrophic (all clients have
    /// the old pubkey pinned).
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(IdentityError::KeyFileWrongSize(bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
    }

    /// Generate a fresh key and write it to `path` with `0600`
    /// permissions. Returns an error if the file already exists —
    /// used by the coord root-key ceremony, which must refuse to
    /// overwrite an existing key.
    pub fn generate_and_persist_new(path: &Path) -> Result<Self, IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let key = Self::generate();
        write_key_file(path, &key.seed())?;
        Ok(key)
    }

    /// Load a key from disk, generating and persisting a new one if
    /// the file does not exist. On Unix the new file is written with
    /// mode `0600`. On other platforms best-effort permissions are
    /// applied via the `std::fs` defaults.
    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(IdentityError::KeyFileWrongSize(bytes.len()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                Ok(Self::from_seed(&seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let key = Self::generate();
                write_key_file(path, &key.seed())?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Ed25519 verifying key wrapper.
#[derive(Debug, Clone)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub fn from_peer_id(peer_id: &PeerId) -> Result<Self, IdentityError> {
        ed25519_dalek::VerifyingKey::from_bytes(peer_id.as_bytes())
            .map(Self)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// X25519 public key (Montgomery form of this Ed25519 key), the
    /// HPKE recipient key for anything sealed to this peer.
    pub fn x25519_public(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }

    pub fn verify(
        &self,
        message: &[u8],
        sig: &ed25519_dalek::Signature,
    ) -> Result<(), IdentityError> {
        self.0
            .verify(message, sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(self.0.to_bytes())
    }
}

#[cfg(unix)]
fn write_key_file(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(seed)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(seed)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::MontgomeryPoint;

    #[test]
    fn x25519_pair_matches() {
        let sk = SigningKey::generate();
        let public = VerifyingKey::from_peer_id(&sk.peer_id())
            .unwrap()
            .x25519_public();
        assert_eq!(
            MontgomeryPoint::mul_base_clamped(sk.x25519_secret()).to_bytes(),
            public
        );
    }
}
