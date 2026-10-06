//! Share store for private routes.
//!
//! `shares.json` lives next to `routes.json` and follows the same
//! persistence discipline:
//! schema-versioned, written mode `0600` via temp-file-then-rename,
//! corrupt files backed up and replaced with an empty store. An
//! empty (or missing, or corrupt) store denies everything — access
//! to a private route is opt-in per (app, peer).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use crate::validate::{validate_app_name, ValidateError};

/// Current on-disk schema version of `shares.json`.
const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Attribution header injected on shared private-route requests:
/// the z-base-32 peer id of the authenticated caller. Shares the
/// `x-p2claw-` prefix with the OAuth identity headers, so the
/// standard inbound strip covers it.
pub const PEER_HEADER: &str = "x-p2claw-peer";

/// One share row: a private route and the peers it is shared with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRecord {
    /// Route name of the private app being shared.
    pub app: String,
    /// z-base-32 peer ids allowed to call it. Explicit list only —
    /// no wildcard.
    pub peers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    shares: Vec<ShareRecord>,
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid peer id `{0}`: {1}")]
    InvalidPeer(String, String),
    #[error("invalid app name `{0}`: {1}")]
    InvalidApp(String, ValidateError),
}

/// In-memory share table. Same shape as `RouteTable`: readers take
/// an `Arc` snapshot; mutations swap a fresh snapshot in and persist
/// on the blocking pool under a write lock. Cloning is `Arc`-cheap.
#[derive(Clone)]
pub struct Shares {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    shares: RwLock<Arc<Vec<ShareRecord>>>,
    write_lock: Mutex<()>,
}

impl Shares {
    /// Load from `path`, or start empty if missing. A corrupt file is
    /// backed up and the store starts empty — which is fail-closed:
    /// an empty store shares nothing.
    pub fn load_or_empty(path: PathBuf) -> Self {
        let shares = match read_from_disk(&path) {
            Ok(v) => v,
            Err(ReadError::Missing) => Vec::new(),
            Err(ReadError::Corrupt(reason)) => {
                let backup = corrupt_backup_path(&path);
                if let Err(e) = fs::rename(&path, &backup) {
                    warn!(
                        path = %path.display(),
                        backup = %backup.display(),
                        error = %e,
                        reason = %reason,
                        "shares.json unreadable; could not move it aside — starting empty (deny-all)"
                    );
                } else {
                    warn!(
                        path = %path.display(),
                        backup = %backup.display(),
                        reason = %reason,
                        "shares.json corrupt; backed up and starting empty (deny-all)"
                    );
                }
                Vec::new()
            }
        };
        Self {
            inner: Arc::new(Inner {
                path,
                shares: RwLock::new(Arc::new(shares)),
                write_lock: Mutex::new(()),
            }),
        }
    }

    /// Snapshot of the current share set.
    pub fn list(&self) -> Vec<ShareRecord> {
        self.snapshot().as_ref().clone()
    }

    /// True iff private route `app` is shared with `peer`
    /// (z-base-32). Deny by default: no row, no access.
    pub fn is_shared(&self, app: &str, peer: &str) -> bool {
        self.snapshot()
            .iter()
            .any(|s| s.app == app && s.peers.iter().any(|p| p == peer))
    }

    /// Replace the whole share set (the `PUT /v1/shares` semantics).
    /// Validates every row before touching memory or disk; duplicate
    /// apps are merged with their peer lists deduplicated, and rows
    /// with no peers are dropped.
    pub async fn replace(&self, shares: Vec<ShareRecord>) -> Result<Vec<ShareRecord>, ShareError> {
        let mut merged: Vec<ShareRecord> = Vec::new();
        for s in shares {
            validate_app_name(&s.app).map_err(|e| ShareError::InvalidApp(s.app.clone(), e))?;
            for p in &s.peers {
                p2claw_identity::PeerId::from_z32(p)
                    .map_err(|e| ShareError::InvalidPeer(p.clone(), e.to_string()))?;
            }
            match merged.iter_mut().find(|m| m.app == s.app) {
                Some(m) => {
                    for p in s.peers {
                        if !m.peers.contains(&p) {
                            m.peers.push(p);
                        }
                    }
                }
                None => {
                    let mut peers = Vec::new();
                    for p in s.peers {
                        if !peers.contains(&p) {
                            peers.push(p);
                        }
                    }
                    merged.push(ShareRecord { app: s.app, peers });
                }
            }
        }
        merged.retain(|s| !s.peers.is_empty());

        let _write = self.inner.write_lock.lock().await;
        let snapshot = Arc::new(merged);
        *self.inner.shares.write().expect("shares lock poisoned") = Arc::clone(&snapshot);
        let path = self.inner.path.clone();
        let to_write = Arc::clone(&snapshot);
        tokio::task::spawn_blocking(move || write_to_disk(&path, &to_write))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
            .map_err(|source| ShareError::Io {
                path: self.inner.path.display().to_string(),
                source,
            })?;
        Ok(snapshot.as_ref().clone())
    }

    fn snapshot(&self) -> Arc<Vec<ShareRecord>> {
        Arc::clone(&self.inner.shares.read().expect("shares lock poisoned"))
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

enum ReadError {
    Missing,
    Corrupt(String),
}

fn read_from_disk(path: &Path) -> Result<Vec<ShareRecord>, ReadError> {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Corrupt(e.to_string())),
    };
    let parsed: OnDisk = match serde_json::from_str(&s) {
        Ok(v) => v,
        Err(e) => return Err(ReadError::Corrupt(e.to_string())),
    };
    if parsed.version != CURRENT_SCHEMA_VERSION {
        return Err(ReadError::Corrupt(format!(
            "unknown schema version {}",
            parsed.version
        )));
    }
    Ok(parsed.shares)
}

fn write_to_disk(path: &Path, shares: &[ShareRecord]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = OnDisk {
        version: CURRENT_SCHEMA_VERSION,
        shares: shares.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&payload)?;
    let tmp = temp_path(path);
    write_file_0600(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    match path.parent() {
        Some(p) => p.join(name),
        None => name.into(),
    }
}

fn corrupt_backup_path(path: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".corrupt.{ts}"));
    match path.parent() {
        Some(p) => p.join(name),
        None => name.into(),
    }
}

#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z32_peer() -> String {
        p2claw_identity::SigningKey::generate().peer_id().to_z32()
    }

    fn share(app: &str, peers: &[&str]) -> ShareRecord {
        ShareRecord {
            app: app.into(),
            peers: peers.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn missing_file_is_empty_and_denies() {
        let dir = tempfile::tempdir().unwrap();
        let s = Shares::load_or_empty(dir.path().join("shares.json"));
        assert!(s.list().is_empty());
        assert!(!s.is_shared("mysvc", &z32_peer()));
    }

    #[tokio::test]
    async fn replace_persists_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shares.json");
        let peer = z32_peer();
        let s = Shares::load_or_empty(path.clone());
        s.replace(vec![share("mysvc", &[&peer])]).await.unwrap();

        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // No stale temp file after the rename.
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "temp file {tmp:?} leaked");

        let s2 = Shares::load_or_empty(path);
        assert!(s2.is_shared("mysvc", &peer));
        assert!(!s2.is_shared("other", &peer));
        assert!(!s2.is_shared("mysvc", &z32_peer()));
    }

    #[tokio::test]
    async fn no_wildcard_peer_matching() {
        // Explicit peers only: "*" is not a valid peer id and must be
        // rejected outright rather than treated as match-all.
        let dir = tempfile::tempdir().unwrap();
        let s = Shares::load_or_empty(dir.path().join("shares.json"));
        let err = s.replace(vec![share("mysvc", &["*"])]).await.unwrap_err();
        assert!(matches!(err, ShareError::InvalidPeer(_, _)), "{err:?}");
        assert!(!s.is_shared("mysvc", "*"));
    }

    #[tokio::test]
    async fn replace_merges_duplicate_apps_and_drops_empty_rows() {
        let dir = tempfile::tempdir().unwrap();
        let a = z32_peer();
        let b = z32_peer();
        let s = Shares::load_or_empty(dir.path().join("shares.json"));
        let saved = s
            .replace(vec![
                share("mysvc", &[&a]),
                share("mysvc", &[&b, &a]),
                share("metrics", &[]),
            ])
            .await
            .unwrap();
        assert_eq!(saved.len(), 1, "empty row dropped, duplicates merged");
        assert_eq!(saved[0].peers, vec![a, b]);
    }

    #[tokio::test]
    async fn replace_rejects_bad_peer_and_bad_app() {
        let dir = tempfile::tempdir().unwrap();
        let s = Shares::load_or_empty(dir.path().join("shares.json"));
        let err = s
            .replace(vec![share("mysvc", &["not-a-peer-id"])])
            .await
            .unwrap_err();
        assert!(matches!(err, ShareError::InvalidPeer(_, _)), "{err:?}");

        let err = s
            .replace(vec![share("Not_Valid", &[&z32_peer()])])
            .await
            .unwrap_err();
        assert!(matches!(err, ShareError::InvalidApp(_, _)), "{err:?}");
        // Failed replace leaves the store untouched.
        assert!(s.list().is_empty());
    }

    #[tokio::test]
    async fn corrupt_file_is_backed_up_and_store_denies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shares.json");
        fs::write(&path, b"not json at all").unwrap();

        let s = Shares::load_or_empty(path);
        assert!(s.list().is_empty());
        assert!(!s.is_shared("mysvc", &z32_peer()));

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
            .collect();
        let backups = entries
            .iter()
            .filter(|n| n.starts_with("shares.json.corrupt."))
            .count();
        assert_eq!(backups, 1, "entries: {entries:?}");
    }

    #[tokio::test]
    async fn unknown_schema_version_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shares.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"version": 99, "shares": []})).unwrap(),
        )
        .unwrap();
        let s = Shares::load_or_empty(path);
        assert!(s.list().is_empty());
    }
}
