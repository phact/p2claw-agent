//! Owner-controlled email settings, persisted as `email.json` in the
//! state directory.
//!
//! The settings are the box's authoritative copy of what coord
//! enforces: whether email is enabled, who may write, and which Gmail
//! accounts may forward. The box sends the whole snapshot to coord
//! after every (re)connect and after each change; coord answers with
//! the box's addresses, which are cached here so they can be shown
//! while offline.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use super::{normalize_address, write_atomic_0600, AddressError};

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// What the box tells coord: the `email_config` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailConfig {
    pub enabled: bool,
    pub allowlist: Vec<String>,
    pub forwarders: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    forwarders: Vec<String>,
    /// Addresses from the last `email_config_ack`.
    #[serde(default)]
    addresses: Vec<String>,
    /// Error from the last `email_config_ack`, if coord refused the
    /// config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_error: Option<String>,
}

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Address(#[from] AddressError),
}

/// Read-mostly settings table: readers take a snapshot, writers
/// serialize through an async lock and persist before returning.
#[derive(Clone)]
pub struct EmailSettings {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    data: RwLock<Arc<OnDisk>>,
    write_lock: Mutex<()>,
}

/// Read-only view of the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub enabled: bool,
    pub allowlist: Vec<String>,
    pub forwarders: Vec<String>,
    pub addresses: Vec<String>,
    pub config_error: Option<String>,
}

impl EmailSettings {
    /// Load from `path`, or start disabled with empty lists. A corrupt
    /// file is backed up and replaced: disabled-with-nothing-allowed is
    /// the fail-closed default.
    pub fn load_or_default(path: PathBuf) -> Self {
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
                warn!(path = %path.display(), error = %e, "email.json unreadable; starting disabled");
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

    pub fn snapshot(&self) -> Snapshot {
        let d = self.data();
        Snapshot {
            enabled: d.enabled,
            allowlist: d.allowlist.clone(),
            forwarders: d.forwarders.clone(),
            addresses: d.addresses.clone(),
            config_error: d.config_error.clone(),
        }
    }

    /// The `email_config` payload for coord.
    pub fn config(&self) -> EmailConfig {
        let d = self.data();
        EmailConfig {
            enabled: d.enabled,
            allowlist: d.allowlist.clone(),
            forwarders: d.forwarders.clone(),
        }
    }

    pub fn addresses(&self) -> Vec<String> {
        self.data().addresses.clone()
    }

    pub async fn set_enabled(&self, enabled: bool) -> Result<(), SettingsError> {
        self.update(|d| d.enabled = enabled).await
    }

    /// Replace the allowlist. Entries are normalized and deduplicated;
    /// one bad entry rejects the whole call and leaves the list as it
    /// was. Returns the stored list.
    pub async fn replace_allowlist(
        &self,
        entries: Vec<String>,
    ) -> Result<Vec<String>, SettingsError> {
        let list = normalize_list(entries)?;
        let stored = list.clone();
        self.update(move |d| d.allowlist = list).await?;
        Ok(stored)
    }

    /// Approve a Gmail account whose forwarded mail is admitted.
    /// Returns the normalized account.
    pub async fn approve_forwarder(&self, account: &str) -> Result<String, SettingsError> {
        let account = normalize_address(account)?;
        let a = account.clone();
        self.update(move |d| {
            if !d.forwarders.contains(&a) {
                d.forwarders.push(a);
            }
        })
        .await?;
        Ok(account)
    }

    /// Stop admitting mail forwarded by `account`. `Ok(false)` when it
    /// wasn't approved.
    pub async fn revoke_forwarder(&self, account: &str) -> Result<bool, SettingsError> {
        let account = normalize_address(account)?;
        let mut removed = false;
        let r = &mut removed;
        self.update(move |d| {
            let before = d.forwarders.len();
            d.forwarders.retain(|f| f != &account);
            *r = d.forwarders.len() != before;
        })
        .await?;
        Ok(removed)
    }

    /// Record coord's answer to the latest `email_config`.
    pub async fn record_ack(
        &self,
        addresses: Vec<String>,
        error: Option<String>,
    ) -> Result<(), SettingsError> {
        self.update(move |d| {
            d.addresses = addresses;
            d.config_error = error;
        })
        .await
    }

    async fn update(&self, f: impl FnOnce(&mut OnDisk)) -> Result<(), SettingsError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = (*self.data()).clone();
        f(&mut next);
        let next = Arc::new(next);
        let bytes = serde_json::to_vec_pretty(&*next).map_err(|e| SettingsError::Io {
            path: self.inner.path.display().to_string(),
            source: io::Error::other(e),
        })?;
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || write_atomic_0600(&path, &bytes))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
            .map_err(|source| SettingsError::Io {
                path: self.inner.path.display().to_string(),
                source,
            })?;
        *self
            .inner
            .data
            .write()
            .expect("email settings lock poisoned") = next;
        Ok(())
    }

    fn data(&self) -> Arc<OnDisk> {
        Arc::clone(
            &self
                .inner
                .data
                .read()
                .expect("email settings lock poisoned"),
        )
    }
}

/// Normalize and deduplicate an allowlist, keeping first-seen order.
pub fn normalize_list(entries: Vec<String>) -> Result<Vec<String>, AddressError> {
    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    for e in entries {
        let n = normalize_address(&e)?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

fn back_up_corrupt(path: &Path, reason: &str) {
    let backup = path.with_extension(format!("json.corrupt.{}", super::now_unix_secs()));
    match fs::rename(path, &backup) {
        Ok(()) => warn!(
            path = %path.display(),
            backup = %backup.display(),
            reason,
            "email.json corrupt; backed up and starting disabled"
        ),
        Err(e) => warn!(
            path = %path.display(),
            error = %e,
            reason,
            "email.json corrupt and could not be moved aside; starting disabled"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn defaults_are_disabled_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = EmailSettings::load_or_default(dir.path().join("email.json"));
        let snap = s.snapshot();
        assert!(!snap.enabled);
        assert!(snap.allowlist.is_empty());
        assert!(snap.forwarders.is_empty());
        assert!(snap.addresses.is_empty());
    }

    #[tokio::test]
    async fn changes_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("email.json");
        let s = EmailSettings::load_or_default(path.clone());
        s.set_enabled(true).await.unwrap();
        let saved = s
            .replace_allowlist(vec![
                "You+tag@Gmail.com".into(),
                "you@gmail.com".into(),
                "b@x.org".into(),
            ])
            .await
            .unwrap();
        assert_eq!(saved, vec!["you@gmail.com", "b@x.org"]);
        assert_eq!(
            s.approve_forwarder("Acct@gmail.com").await.unwrap(),
            "acct@gmail.com"
        );
        s.record_ack(vec!["alias@p2claw.com".into()], None)
            .await
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let s2 = EmailSettings::load_or_default(path);
        let snap = s2.snapshot();
        assert!(snap.enabled);
        assert_eq!(snap.allowlist, vec!["you@gmail.com", "b@x.org"]);
        assert_eq!(snap.forwarders, vec!["acct@gmail.com"]);
        assert_eq!(snap.addresses, vec!["alias@p2claw.com"]);
        assert_eq!(
            s2.config(),
            EmailConfig {
                enabled: true,
                allowlist: vec!["you@gmail.com".into(), "b@x.org".into()],
                forwarders: vec!["acct@gmail.com".into()],
            }
        );
    }

    #[tokio::test]
    async fn bad_entry_rejects_whole_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let s = EmailSettings::load_or_default(dir.path().join("email.json"));
        s.replace_allowlist(vec!["a@x.org".into()]).await.unwrap();
        let err = s
            .replace_allowlist(vec!["b@x.org".into(), "nope".into()])
            .await
            .unwrap_err();
        assert!(matches!(err, SettingsError::Address(_)), "{err:?}");
        assert_eq!(s.snapshot().allowlist, vec!["a@x.org"]);
    }

    #[tokio::test]
    async fn revoke_reports_whether_it_removed() {
        let dir = tempfile::tempdir().unwrap();
        let s = EmailSettings::load_or_default(dir.path().join("email.json"));
        s.approve_forwarder("a@gmail.com").await.unwrap();
        assert!(s.revoke_forwarder("A@gmail.com").await.unwrap());
        assert!(!s.revoke_forwarder("a@gmail.com").await.unwrap());
    }

    #[tokio::test]
    async fn corrupt_file_is_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("email.json");
        fs::write(&path, b"{nope").unwrap();
        let s = EmailSettings::load_or_default(path);
        assert!(!s.snapshot().enabled);
        let backups = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert_eq!(backups, 1);
    }
}
