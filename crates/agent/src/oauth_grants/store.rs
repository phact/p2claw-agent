//! Agent-managed grants, persisted as `oauth-grants.json` (0600) in
//! the state directory.
//!
//! A grant blob is opaque to the box and only the broker can open it,
//! but it still refreshes into live access tokens for whoever holds
//! this box's identity key, so the file gets the same handling as the
//! key: owner-only mode, atomic replacement, never listed in full.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use crate::fs_atomic::write_atomic_0600;

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// One stored grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGrant {
    pub id: String,
    pub provider: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The broker-sealed grant, verbatim.
    pub grant: String,
    /// Unix seconds.
    pub created_at: u64,
}

/// What listings expose: everything but the blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantSummary {
    pub id: String,
    pub provider: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
}

impl From<&StoredGrant> for GrantSummary {
    fn from(g: &StoredGrant) -> Self {
        Self {
            id: g.id.clone(),
            provider: g.provider.clone(),
            scopes: g.scopes.clone(),
            created_at: g.created_at,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    #[serde(default)]
    grants: Vec<StoredGrant>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Read-mostly table: readers take a snapshot, writers serialize
/// through an async lock and persist before returning.
#[derive(Clone)]
pub struct GrantStore {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    data: RwLock<Arc<OnDisk>>,
    write_lock: Mutex<()>,
}

impl GrantStore {
    /// Load from `path`, or start empty. A corrupt file is moved
    /// aside rather than overwritten, so the grants in it can still be
    /// recovered by hand.
    pub fn load_or_empty(path: PathBuf) -> Self {
        let data = match fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str::<OnDisk>(&s) {
                Ok(d) if d.version == CURRENT_SCHEMA_VERSION => d,
                Ok(d) => {
                    back_up_corrupt(&path, &format!("unknown schema version {}", d.version));
                    OnDisk::default()
                }
                Err(e) => {
                    back_up_corrupt(&path, &e.to_string());
                    OnDisk::default()
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => OnDisk::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "oauth-grants.json unreadable; starting empty");
                OnDisk::default()
            }
        };
        Self {
            inner: Arc::new(Inner {
                path,
                data: RwLock::new(Arc::new(OnDisk {
                    version: CURRENT_SCHEMA_VERSION,
                    ..data
                })),
                write_lock: Mutex::new(()),
            }),
        }
    }

    pub fn list(&self) -> Vec<GrantSummary> {
        self.data().grants.iter().map(GrantSummary::from).collect()
    }

    pub fn get(&self, id: &str) -> Option<StoredGrant> {
        self.data().grants.iter().find(|g| g.id == id).cloned()
    }

    pub async fn insert(&self, grant: StoredGrant) -> Result<(), StoreError> {
        self.update(move |d| {
            d.grants.retain(|g| g.id != grant.id);
            d.grants.push(grant);
        })
        .await
    }

    /// Swap the blob after the provider rotated the refresh token.
    /// `Ok(false)` when the grant is gone.
    pub async fn replace_blob(&self, id: &str, blob: String) -> Result<bool, StoreError> {
        let mut found = false;
        let f = &mut found;
        self.update(move |d| {
            if let Some(g) = d.grants.iter_mut().find(|g| g.id == id) {
                g.grant = blob;
                *f = true;
            }
        })
        .await?;
        Ok(found)
    }

    /// `Ok(false)` when there was nothing to remove.
    pub async fn remove(&self, id: &str) -> Result<bool, StoreError> {
        let mut removed = false;
        let r = &mut removed;
        self.update(move |d| {
            let before = d.grants.len();
            d.grants.retain(|g| g.id != id);
            *r = d.grants.len() != before;
        })
        .await?;
        Ok(removed)
    }

    async fn update(&self, f: impl FnOnce(&mut OnDisk)) -> Result<(), StoreError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = (*self.data()).clone();
        f(&mut next);
        let next = Arc::new(next);
        let bytes = serde_json::to_vec_pretty(&*next).map_err(|e| StoreError::Io {
            path: self.inner.path.display().to_string(),
            source: io::Error::other(e),
        })?;
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || write_atomic_0600(&path, &bytes))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
            .map_err(|source| StoreError::Io {
                path: self.inner.path.display().to_string(),
                source,
            })?;
        *self.inner.data.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    fn data(&self) -> Arc<OnDisk> {
        Arc::clone(&self.inner.data.read().unwrap_or_else(|e| e.into_inner()))
    }
}

fn back_up_corrupt(path: &std::path::Path, reason: &str) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = path.with_extension(format!("json.corrupt.{stamp}"));
    match fs::rename(path, &backup) {
        Ok(()) => warn!(
            path = %path.display(),
            backup = %backup.display(),
            reason,
            "oauth-grants.json corrupt; backed up and starting empty"
        ),
        Err(e) => warn!(
            path = %path.display(),
            error = %e,
            reason,
            "oauth-grants.json corrupt and could not be moved aside; starting empty"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: &str) -> StoredGrant {
        StoredGrant {
            id: id.into(),
            provider: "google".into(),
            scopes: vec!["calendar.app.created".into()],
            grant: format!("g1.k1.secret-{id}"),
            created_at: 1_791_126_131,
        }
    }

    #[tokio::test]
    async fn persists_with_owner_only_mode_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth-grants.json");
        let s = GrantStore::load_or_empty(path.clone());
        assert!(s.list().is_empty());
        s.insert(grant("gr_1")).await.unwrap();
        s.insert(grant("gr_2")).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            !path.with_extension("json.tmp").exists(),
            "temp file left behind"
        );

        let s2 = GrantStore::load_or_empty(path);
        assert_eq!(s2.get("gr_1"), Some(grant("gr_1")));
        assert_eq!(
            s2.list(),
            vec![
                GrantSummary::from(&grant("gr_1")),
                GrantSummary::from(&grant("gr_2"))
            ]
        );
    }

    #[tokio::test]
    async fn listing_never_carries_the_blob() {
        let dir = tempfile::tempdir().unwrap();
        let s = GrantStore::load_or_empty(dir.path().join("oauth-grants.json"));
        s.insert(grant("gr_1")).await.unwrap();
        let json = serde_json::to_string(&s.list()).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert!(!json.contains("\"grant\""), "{json}");
    }

    #[tokio::test]
    async fn replace_and_remove_report_presence() {
        let dir = tempfile::tempdir().unwrap();
        let s = GrantStore::load_or_empty(dir.path().join("oauth-grants.json"));
        s.insert(grant("gr_1")).await.unwrap();
        assert!(s
            .replace_blob("gr_1", "g1.k2.rotated".into())
            .await
            .unwrap());
        assert!(!s.replace_blob("gr_9", "x".into()).await.unwrap());
        assert_eq!(s.get("gr_1").unwrap().grant, "g1.k2.rotated");
        assert!(s.remove("gr_1").await.unwrap());
        assert!(!s.remove("gr_1").await.unwrap());
        assert!(s.get("gr_1").is_none());
    }

    #[tokio::test]
    async fn insert_replaces_an_existing_id() {
        let dir = tempfile::tempdir().unwrap();
        let s = GrantStore::load_or_empty(dir.path().join("oauth-grants.json"));
        s.insert(grant("gr_1")).await.unwrap();
        let mut g = grant("gr_1");
        g.scopes.push("extra".into());
        s.insert(g.clone()).await.unwrap();
        assert_eq!(s.list().len(), 1);
        assert_eq!(s.get("gr_1"), Some(g));
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth-grants.json");
        fs::write(&path, b"{nope").unwrap();
        let s = GrantStore::load_or_empty(path.clone());
        assert!(s.list().is_empty());
        assert!(!path.exists());
        let backups = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert_eq!(backups, 1);
    }
}
