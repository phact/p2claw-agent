//! Per-installation CA root + on-demand leaf cert minting for the
//! local 443 SNI listener.
//!
//! ## Why a local CA
//!
//! `curl https://app-X.<parent>/...` from a local app expects a TLS
//! chain the OS trusts. Per-box ACME doesn't scale operationally;
//! wildcard distribution is too wide a blast radius; TLS-passthrough
//! to a per-app cert breaks the "app code unchanged" goal.
//!
//! Solution (Tailscale-MagicDNS-HTTPS / mkcert / Caddy local-mode
//! pattern): generate a **per-installation** CA root at install time,
//! add it to the system trust store (done by the platform-install
//! code), and mint per-SNI leaf certs on demand at the SNI listener.
//! The CA root private key never leaves the box, so the blast
//! radius is one installation. Uninstall removes the trust-store
//! entry and deletes the key.
//!
//! ## What this module owns
//!
//! - [`LocalCa::load_or_generate`]: persist a CA root keypair + cert
//!   to disk on first run (mode 0600 on the key, mirroring
//!   `state_store.rs`'s `control_token` discipline). Subsequent
//!   starts load it.
//! - [`LocalCa::server_config_for`]: mint a leaf cert for the given
//!   SNI, cached by SNI so a hot app pays cert-gen cost once. Returns
//!   an `Arc<rustls::ServerConfig>` ready to drive
//!   `tokio_rustls::StartHandshake::into_stream`.
//! - [`LocalCa::root_cert_pem`]: the PEM-encoded root cert, for
//!   the platform-install code to install into the OS trust store.
//!
//! ## What this module does NOT own
//!
//! - System-trust-store install + uninstall — platform-install code.
//! - The `Dispatcher` impl that wires the SNI listener to the cert
//!   minter and to the outbound Iroh dialer — the peer dialer and
//!   the small glue layer it ships with.
//!
//! ## Cert shape
//!
//! - **Root**: ECDSA P-256 (NIST P-256 / secp256r1) keypair.
//!   Self-signed, validity = 10 years from issue,
//!   `BasicConstraints: CA: TRUE`. Stored at
//!   `<config_dir>/local_ca.{key,crt}`.
//! - **Leaf**: ECDSA P-256 keypair (per-SNI, generated fresh),
//!   validity ~30 days, `SubjectAlternativeName: DNS:<sni>`,
//!   `ExtendedKeyUsage: serverAuth`. Cached by SNI string in an
//!   in-memory `Mutex<HashMap>`.
//!
//! **Why ECDSA P-256 and not Ed25519**: macOS's
//! `security add-trusted-cert` (and the underlying
//! `SecCertificateAddToKeychain` API) refuses Ed25519 certificates
//! with `Unknown format in import`. Apple's trust-store APIs only
//! accept RSA and ECDSA (P-256 / P-384 / P-521). Ed25519 is fine
//! for our identity-key scheme (where we control both ends), but
//! the local CA serves browser + OS trust paths — Apple-imposed
//! acceptance rules apply. P-256 is the most-supported curve
//! across macOS Keychain, Linux `update-ca-certificates`, Windows
//! certmgr, and rustls's ring crypto provider.
//!
//! **Migration**: existing installs (any version that minted with
//! the prior Ed25519 root) MUST wipe `local_ca.{crt,key}` from the
//! agent's data dir before re-running `service install --system`.
//! Otherwise the agent reuses the Ed25519 root from disk and the
//! macOS install step still fails. Operator-facing release notes
//! call this out.
//!
//! Leaf TTL of 30 days is a knowingly conservative compromise —
//! cached forever would be simplest, but nudges us closer to
//! "rotate occasionally so a leaked leaf has a bounded blast
//! radius." 30 days matches Let's Encrypt's standard cadence and
//! is shorter than the agent's typical uptime (months), so the
//! cache will naturally re-mint on rotation. Preemptive rotation is
//! not implemented; the cache entry just expires and the next
//! request mints fresh.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Validity for the per-installation CA root. 10 years matches
/// mkcert's default and is much longer than any agent install is
/// expected to live; rotation would mean re-installing in the system
/// trust store anyway.
const ROOT_VALIDITY_DAYS: i64 = 365 * 10;

/// Validity for per-SNI leaf certs. 30 days mirrors Let's Encrypt's
/// standard cadence; cache entries past this point get re-minted.
const LEAF_VALIDITY_DAYS: i64 = 30;

/// Filenames inside the agent's data dir.
const ROOT_KEY_FILENAME: &str = "local_ca.key";
const ROOT_CERT_FILENAME: &str = "local_ca.crt";

#[derive(Debug, Error)]
pub enum LocalCaError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cert generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls config: {0}")]
    Rustls(String),
    #[error("system clock is before the unix epoch: {0}")]
    Clock(String),
}

/// Cache entry for a minted leaf cert + the rustls config that
/// embeds it. Stored behind an `Arc<ServerConfig>` so the SNI
/// listener can hand the same config to multiple in-flight
/// connections without re-cloning the cert chain.
struct LeafEntry {
    config: Arc<ServerConfig>,
    /// When the leaf cert expires. Used to evict stale entries on
    /// the next request rather than running a background sweep.
    not_after: OffsetDateTime,
}

/// Per-installation local CA. Cheap to clone (internal `Arc`); the
/// SNI dispatcher owns one handle, tests own another.
#[derive(Clone)]
pub struct LocalCa {
    inner: Arc<LocalCaInner>,
}

struct LocalCaInner {
    /// CA root keypair — signs every leaf. Never leaves the box.
    root_key: KeyPair,
    /// CA root cert — stays in memory for `signed_by(&pubkey,
    /// &issuer_cert, &issuer_key)` calls; also the source of
    /// [`LocalCa::root_cert_pem`] for the install-time trust-store
    /// hookup.
    root_cert: rcgen::Certificate,
    /// Root cert PEM, computed once at construction (cheap to keep
    /// hot for repeated `root_cert_pem()` calls from the
    /// platform-install path).
    root_pem: String,
    /// Cache of per-SNI minted configs. Evicted on the next request
    /// after [`LeafEntry::not_after`] passes.
    leaves: Mutex<HashMap<String, LeafEntry>>,
}

impl LocalCa {
    /// Load the CA from disk if present at `data_dir`, else generate
    /// a fresh one and persist it. The key file is mode-0600 on Unix
    /// (mirrors `state_store.rs::write_file_0600`'s discipline since
    /// the CA root key is just as sensitive as a bearer credential).
    pub fn load_or_generate(data_dir: &Path) -> Result<Self, LocalCaError> {
        let key_path = data_dir.join(ROOT_KEY_FILENAME);
        let cert_path = data_dir.join(ROOT_CERT_FILENAME);

        if key_path.exists() && cert_path.exists() {
            debug!(?key_path, ?cert_path, "local-ca: loading existing root");
            return Self::load(&key_path, &cert_path);
        }

        info!(
            ?data_dir,
            "local-ca: generating fresh per-installation root"
        );
        Self::generate_and_persist(data_dir, &key_path, &cert_path)
    }

    fn load(key_path: &Path, cert_path: &Path) -> Result<Self, LocalCaError> {
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| LocalCaError::Io {
            path: key_path.display().to_string(),
            source: e,
        })?;
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| LocalCaError::Io {
            path: cert_path.display().to_string(),
            source: e,
        })?;
        let root_key = KeyPair::from_pem(&key_pem)?;
        // Re-parse the cert PEM by way of CertificateParams so we
        // can re-emit a `Certificate` structure (rcgen 0.13 doesn't
        // expose a direct `Certificate::from_pem`; the params-then-
        // self_signed round-trip with the existing key gives us back
        // the same cert byte-for-byte).
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let root_cert = params.self_signed(&root_key)?;
        let root_pem = cert_pem; // already PEM, just cache the string
        Ok(Self {
            inner: Arc::new(LocalCaInner {
                root_key,
                root_cert,
                root_pem,
                leaves: Mutex::new(HashMap::new()),
            }),
        })
    }

    fn generate_and_persist(
        data_dir: &Path,
        key_path: &Path,
        cert_path: &Path,
    ) -> Result<Self, LocalCaError> {
        std::fs::create_dir_all(data_dir).map_err(|e| LocalCaError::Io {
            path: data_dir.display().to_string(),
            source: e,
        })?;

        // ECDSA P-256, not Ed25519 — see module doc-comment
        // (`Cert shape` section). macOS Keychain rejects Ed25519
        // CA certs with `Unknown format in import`; P-256 is the
        // most-portable choice across macOS / Linux / Windows trust
        // stores + rustls's ring provider.
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // Recognizable subject in case an operator inspects the
        // cert via `openssl x509`. Common Name is purely cosmetic
        // for CA roots — modern verifiers consult SAN — so the
        // string is a label, not a hostname commitment.
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "p2claw local CA");
        dn.push(DnType::OrganizationName, "p2claw");
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now
            .checked_add(TimeDuration::days(ROOT_VALIDITY_DAYS))
            .unwrap_or(now);

        let root_cert = params.self_signed(&root_key)?;

        // Persist key (mode 0600 on Unix) + cert (world-readable).
        let key_pem = root_key.serialize_pem();
        write_file_0600(key_path, key_pem.as_bytes())?;
        let cert_pem = root_cert.pem();
        std::fs::write(cert_path, cert_pem.as_bytes()).map_err(|e| LocalCaError::Io {
            path: cert_path.display().to_string(),
            source: e,
        })?;

        Ok(Self {
            inner: Arc::new(LocalCaInner {
                root_key,
                root_cert,
                root_pem: cert_pem,
                leaves: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// PEM encoding of the root cert. The platform-install code
    /// reads this and installs it in the system trust store at
    /// install time; the matching uninstall removes it.
    pub fn root_cert_pem(&self) -> &str {
        &self.inner.root_pem
    }

    /// Mint (or return cached) `ServerConfig` for the given SNI.
    /// The returned `Arc<ServerConfig>` is fed into
    /// `tokio_rustls::StartHandshake::into_stream(server_config)` to
    /// complete the TLS handshake.
    ///
    /// Cache eviction is lazy: a stale entry (past `not_after`)
    /// gets re-minted on the next request. No background sweeper —
    /// stale entries cost an in-memory `LeafEntry` until something
    /// touches the SNI again, and we cap implicitly via the SNI
    /// space (which is bounded by how many distinct apps a box
    /// installs).
    pub async fn server_config_for(&self, sni: &str) -> Result<Arc<ServerConfig>, LocalCaError> {
        let now = OffsetDateTime::now_utc();
        {
            let leaves = self.inner.leaves.lock().await;
            if let Some(entry) = leaves.get(sni) {
                if entry.not_after > now {
                    return Ok(Arc::clone(&entry.config));
                }
                debug!(%sni, "local-ca: cached leaf expired; re-minting");
            }
        }

        let (config, not_after) = self.mint_leaf(sni, now)?;
        let arc = Arc::new(config);
        let mut leaves = self.inner.leaves.lock().await;
        leaves.insert(
            sni.to_string(),
            LeafEntry {
                config: Arc::clone(&arc),
                not_after,
            },
        );
        Ok(arc)
    }

    /// Generate a fresh leaf cert + ServerConfig for `sni`. Pure —
    /// caller does the cache bookkeeping.
    fn mint_leaf(
        &self,
        sni: &str,
        now: OffsetDateTime,
    ) -> Result<(ServerConfig, OffsetDateTime), LocalCaError> {
        // ECDSA P-256 leaves match the root's algorithm.
        // Ed25519 leaves chained off an ECDSA root WOULD validate
        // (chain verification doesn't require key-type uniformity)
        // but mixing curves complicates rustls's signature-scheme
        // negotiation. Single-algo chain keeps the SNI handshake
        // path predictable.
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut leaf_params = CertificateParams::new(vec![sni.to_string()])?;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        leaf_params.distinguished_name = dn;
        leaf_params.not_before = now;
        let not_after = now
            .checked_add(TimeDuration::days(LEAF_VALIDITY_DAYS))
            .unwrap_or(now);
        leaf_params.not_after = not_after;

        let leaf_cert =
            leaf_params.signed_by(&leaf_key, &self.inner.root_cert, &self.inner.root_key)?;

        // Build the rustls ServerConfig. Chain = [leaf, root] so
        // clients see the full chain (root included for self-served
        // installs that don't need OS trust-store lookup; harmless
        // when they do).
        let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
        let root_der: CertificateDer<'static> = self.inner.root_cert.der().clone();
        let chain = vec![leaf_der, root_der];
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .map_err(|e| LocalCaError::Rustls(e.to_string()))?;
        Ok((config, not_after))
    }
}

// ---------- internal helpers --------------------------------------

/// Write `bytes` to `path` with mode 0600 on Unix. Mirrors
/// `state_store.rs::write_file_0600` — the CA root private key is
/// the same trust class as the agent's identity key.
#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), LocalCaError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| LocalCaError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    f.write_all(bytes).map_err(|e| LocalCaError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    f.sync_all().map_err(|e| LocalCaError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), LocalCaError> {
    std::fs::write(path, bytes).map_err(|e| LocalCaError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

// Acknowledge `PathBuf` in scope for callers that want to compose
// paths against the constants. (The constants are module-private,
// so this is mostly forward-compat for the platform-install code.)
#[allow(dead_code)]
pub(crate) fn root_key_filename() -> PathBuf {
    PathBuf::from(ROOT_KEY_FILENAME)
}
#[allow(dead_code)]
pub(crate) fn root_cert_filename() -> PathBuf {
    PathBuf::from(ROOT_CERT_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    fn fresh_ca() -> (LocalCa, tempfile::TempDir) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_generate(dir.path()).unwrap();
        (ca, dir)
    }

    /// Pin the cert algorithm at the keypair level. macOS's
    /// Keychain rejects Ed25519 with `Unknown format in import`
    /// — a future "let's go back to Ed25519" edit would silently
    /// re-break the macOS install path. This regression fires
    /// loudly via `KeyPair::algorithm()` on the persisted root
    /// key, so the deploy-blocker bug class can't recur.
    #[test]
    fn root_keypair_is_ecdsa_p256_not_ed25519() {
        let (_ca, dir) = fresh_ca();
        let key_path = dir.path().join(ROOT_KEY_FILENAME);
        let pem = std::fs::read_to_string(&key_path).expect("root key persisted");
        let kp = KeyPair::from_pem(&pem).expect("root key PEM parses");
        let alg = kp.algorithm();
        assert!(
            std::ptr::eq(alg, &PKCS_ECDSA_P256_SHA256),
            "root key algorithm must be PKCS_ECDSA_P256_SHA256; got {alg:?} \
             — Ed25519 is rejected by macOS Keychain"
        );
    }

    #[test]
    fn generate_writes_root_files_with_correct_modes() {
        let (_ca, dir) = fresh_ca();
        let key_path = dir.path().join(ROOT_KEY_FILENAME);
        let cert_path = dir.path().join(ROOT_CERT_FILENAME);
        assert!(key_path.exists(), "root key must be persisted");
        assert!(cert_path.exists(), "root cert must be persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let key_mode = std::fs::metadata(&key_path).unwrap().mode() & 0o777;
            assert_eq!(key_mode, 0o600, "CA root key must be 0600");
        }
    }

    #[test]
    fn root_cert_pem_starts_with_pem_marker() {
        let (ca, _dir) = fresh_ca();
        let pem = ca.root_cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem:.80}");
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[tokio::test]
    async fn second_load_reuses_persisted_root() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let first = LocalCa::load_or_generate(dir.path()).unwrap();
        let pem_first = first.root_cert_pem().to_string();
        // Drop and reload — second invocation must read from disk,
        // not re-generate. Compare the cert PEM byte-for-byte.
        drop(first);
        let second = LocalCa::load_or_generate(dir.path()).unwrap();
        assert_eq!(
            pem_first,
            second.root_cert_pem(),
            "load_or_generate on a populated dir must NOT regenerate"
        );
    }

    /// End-to-end: drive a real TLS handshake between a client that
    /// trusts the local CA root and a server using the minted
    /// `ServerConfig`. Handshake success proves both:
    ///   1. The leaf cert validates against the root (chain is correct).
    ///   2. The leaf cert's SAN matches the SNI the client used.
    /// Stronger than poking at the cert DER bytes from outside.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mint_leaf_handshakes_with_a_client_trusting_the_root() {
        let (ca, _dir) = fresh_ca();
        let sni = "recipes-blue-otter-7392.p2claw.com";
        let server_config = ca.server_config_for(sni).await.unwrap();

        // Build a client RootCertStore that trusts ONLY our local
        // CA root. If the leaf isn't signed by the root we just
        // installed, the handshake fails on cert verification.
        let mut roots = rustls::RootCertStore::empty();
        let root_pem = ca.root_cert_pem();
        // Parse the PEM ourselves to avoid pulling in rustls-pemfile.
        let root_der = pem_to_der(root_pem);
        roots
            .add(rustls::pki_types::CertificateDer::from(root_der))
            .unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // In-process handshake over a tokio::io::duplex pair.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_cfg = Arc::clone(&server_config);
        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            acceptor.accept(server_io).await
        });
        let client_task = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(sni.to_string()).unwrap();
            connector.connect(server_name, client_io).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let _server_stream = server_res
            .expect("server task panic")
            .expect("server-side handshake failed");
        let _client_stream = client_res
            .expect("client task panic")
            .expect("client-side handshake failed — leaf may not validate against root");
    }

    #[tokio::test]
    async fn server_config_for_caches_subsequent_requests() {
        let (ca, _dir) = fresh_ca();
        let sni = "recipes-blue-otter-7392.p2claw.com";
        let first = ca.server_config_for(sni).await.unwrap();
        let second = ca.server_config_for(sni).await.unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "second request for the same SNI must return the cached Arc"
        );
    }

    #[tokio::test]
    async fn server_config_for_distinct_snis_mints_distinct_certs() {
        let (ca, _dir) = fresh_ca();
        let a = ca
            .server_config_for("recipes-blue-otter-7392.p2claw.com")
            .await
            .unwrap();
        let b = ca
            .server_config_for("homelab-blue-otter-7392.p2claw.com")
            .await
            .unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different SNIs must produce different ServerConfigs"
        );
    }

    /// Decode a single-cert PEM block to DER. Trivial parser to
    /// avoid pulling in `rustls-pemfile` as a test dep — we control
    /// the input shape (it's the PEM we just emitted from rcgen).
    fn pem_to_der(pem: &str) -> Vec<u8> {
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        let start = pem.find(begin).expect("BEGIN marker") + begin.len();
        let stop = pem.find(end).expect("END marker");
        let b64: String = pem[start..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .expect("base64")
    }
}
