//! The box inbox: delivered mail and Gmail forwarding requests under
//! `<state dir>/mail/`.
//!
//! Layout: `index.json` (one row per message or expired summary, no
//! bodies), `<id>.eml` (the raw RFC 5322 bytes) and `forwarding.json`
//! (confirmation requests, owner-only). Everything is written mode
//! 0600 via temp-file-then-rename. The index is the source of truth
//! for what exists; an `.eml` without a row is ignored.
//!
//! Nothing expires here. `ack` marks a message handled; only `delete`
//! removes it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use p2claw_email_proto::{Auth, Metadata, Summary};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, Mutex};
use tracing::warn;

use super::render;
use super::{now_unix_secs, write_atomic_0600};

const CURRENT_SCHEMA_VERSION: u32 = 1;
const WATCH_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Delivered mail; the raw bytes are on disk.
    Message,
    /// Coord's summary of mail whose body expired before the box
    /// fetched it. No body, no raw bytes.
    Expired,
}

/// One index row. Bodies and attachments are parsed from the raw
/// bytes on demand; the subject and attachment count are cached so
/// listing stays cheap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub kind: EntryKind,
    /// Unix seconds, as stamped by the Worker.
    pub received_at: u64,
    /// Unix seconds when the box stored it.
    pub stored_at: u64,
    #[serde(default)]
    pub to: String,
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_by: Option<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    #[serde(default)]
    pub acked: bool,
    /// Raw message size in bytes; 0 for expired entries.
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub attachment_count: u32,
}

/// A Gmail forwarding confirmation: the account that wants to forward
/// and the bearer link that approves it. The link is a secret; it is
/// shown to the owner only and never logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingRequest {
    pub id: String,
    /// Requesting Gmail account, when the message named one.
    pub account: Option<String>,
    pub link: Option<String>,
    pub received_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexOnDisk {
    version: u32,
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ForwardingOnDisk {
    version: u32,
    requests: Vec<ForwardingRequest>,
}

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid message id `{0}`")]
    BadId(String),
    #[error("no message `{0}`")]
    NotFound(String),
}

#[derive(Clone)]
pub struct Inbox {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    entries: RwLock<Arc<Vec<Entry>>>,
    requests: RwLock<Arc<Vec<ForwardingRequest>>>,
    write_lock: Mutex<()>,
    new_ids: broadcast::Sender<String>,
}

impl Inbox {
    /// Load the inbox under `dir`, or start empty. Corrupt index files
    /// are backed up and the inbox starts empty; the `.eml` files stay
    /// on disk for manual recovery.
    pub fn load_or_empty(dir: PathBuf) -> Self {
        let entries = load_json::<IndexOnDisk>(&dir.join("index.json"))
            .map(|d| d.entries)
            .unwrap_or_default();
        let requests = load_json::<ForwardingOnDisk>(&dir.join("forwarding.json"))
            .map(|d| d.requests)
            .unwrap_or_default();
        let (new_ids, _) = broadcast::channel(WATCH_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                dir,
                entries: RwLock::new(Arc::new(entries)),
                requests: RwLock::new(Arc::new(requests)),
                write_lock: Mutex::new(()),
                new_ids,
            }),
        }
    }

    /// Ids of newly stored entries (messages and expired summaries),
    /// for `watch`. A slow subscriber that falls more than
    /// `WATCH_CAPACITY` ids behind sees a lag error and should catch up
    /// with an unread listing.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.inner.new_ids.subscribe()
    }

    /// All entries, newest first. `unread_only` drops acked ones.
    pub fn list(&self, unread_only: bool) -> Vec<Entry> {
        let mut v: Vec<Entry> = self
            .entries()
            .iter()
            .filter(|e| !unread_only || !e.acked)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v
    }

    pub fn get(&self, id: &str) -> Option<Entry> {
        self.entries().iter().find(|e| e.id == id).cloned()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.entries().iter().any(|e| e.id == id)
    }

    pub fn unread_count(&self) -> usize {
        self.entries().iter().filter(|e| !e.acked).count()
    }

    /// Raw RFC 5322 bytes of a stored message. Expired entries have
    /// none and answer `NotFound`.
    pub async fn raw(&self, id: &str) -> Result<Vec<u8>, InboxError> {
        let entry = self
            .get(id)
            .ok_or_else(|| InboxError::NotFound(id.to_string()))?;
        if entry.kind != EntryKind::Message {
            return Err(InboxError::NotFound(id.to_string()));
        }
        let path = self.raw_path(id)?;
        tokio::fs::read(&path)
            .await
            .map_err(|source| InboxError::Io {
                path: path.display().to_string(),
                source,
            })
    }

    /// Store a delivered message. Idempotent on `meta.id`: a second
    /// delivery of the same id returns the existing row untouched.
    pub async fn store_message(&self, meta: &Metadata, raw: &[u8]) -> Result<Entry, InboxError> {
        validate_id(&meta.id)?;
        let _write = self.inner.write_lock.lock().await;
        if let Some(existing) = self.get(&meta.id) {
            return Ok(existing);
        }
        let headline = render::headline(raw);
        let entry = Entry {
            id: meta.id.clone(),
            kind: EntryKind::Message,
            received_at: meta.received_at,
            stored_at: now_unix_secs(),
            to: meta.to.clone(),
            from: meta.from.clone(),
            forwarded_by: meta.forwarded_by.clone(),
            subject: headline.subject,
            auth: Some(meta.auth.clone()),
            acked: false,
            size: raw.len() as u64,
            attachment_count: headline.attachment_count,
        };
        let raw_path = self.raw_path(&meta.id)?;
        let raw_owned = raw.to_vec();
        let rp = raw_path.clone();
        tokio::task::spawn_blocking(move || write_atomic_0600(&rp, &raw_owned))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
            .map_err(|source| InboxError::Io {
                path: raw_path.display().to_string(),
                source,
            })?;
        let mut next = (*self.entries()).clone();
        next.push(entry.clone());
        self.persist_entries(next).await?;
        let _ = self.inner.new_ids.send(entry.id.clone());
        Ok(entry)
    }

    /// Record mail that expired on coord before the box fetched it.
    /// Idempotent on `summary.id`.
    pub async fn record_expired(&self, summary: &Summary) -> Result<Entry, InboxError> {
        validate_id(&summary.id)?;
        let _write = self.inner.write_lock.lock().await;
        if let Some(existing) = self.get(&summary.id) {
            return Ok(existing);
        }
        let entry = Entry {
            id: summary.id.clone(),
            kind: EntryKind::Expired,
            received_at: summary.received_at,
            stored_at: now_unix_secs(),
            to: String::new(),
            from: summary.from.clone(),
            forwarded_by: None,
            subject: summary.subject.clone(),
            auth: None,
            acked: false,
            size: 0,
            attachment_count: 0,
        };
        let mut next = (*self.entries()).clone();
        next.push(entry.clone());
        self.persist_entries(next).await?;
        let _ = self.inner.new_ids.send(entry.id.clone());
        Ok(entry)
    }

    /// Mark a message handled. It stays until deleted.
    pub async fn ack(&self, id: &str) -> Result<Entry, InboxError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = (*self.entries()).clone();
        let Some(e) = next.iter_mut().find(|e| e.id == id) else {
            return Err(InboxError::NotFound(id.to_string()));
        };
        if e.acked {
            return Ok(e.clone());
        }
        e.acked = true;
        let updated = e.clone();
        self.persist_entries(next).await?;
        Ok(updated)
    }

    /// Remove a message and its raw bytes.
    pub async fn delete(&self, id: &str) -> Result<(), InboxError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = (*self.entries()).clone();
        let before = next.len();
        next.retain(|e| e.id != id);
        if next.len() == before {
            return Err(InboxError::NotFound(id.to_string()));
        }
        self.persist_entries(next).await?;
        if let Ok(path) = self.raw_path(id) {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "inbox: could not remove raw message")
                }
            }
        }
        Ok(())
    }

    // ---- forwarding requests ------------------------------------------

    pub fn forwarding_requests(&self) -> Vec<ForwardingRequest> {
        let mut v = (*self.requests()).clone();
        v.sort_by_key(|r| std::cmp::Reverse(r.received_at));
        v
    }

    /// Keep a confirmation request for the owner. Idempotent on id.
    pub async fn store_forwarding_request(&self, req: ForwardingRequest) -> Result<(), InboxError> {
        validate_id(&req.id)?;
        let _write = self.inner.write_lock.lock().await;
        if self.requests().iter().any(|r| r.id == req.id) {
            return Ok(());
        }
        let mut next = (*self.requests()).clone();
        next.push(req);
        self.persist_requests(next).await
    }

    /// Drop the requests from `account`, once the owner has acted on
    /// them. Returns how many were removed.
    pub async fn remove_forwarding_requests(&self, account: &str) -> Result<usize, InboxError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = (*self.requests()).clone();
        let before = next.len();
        next.retain(|r| r.account.as_deref() != Some(account));
        let removed = before - next.len();
        if removed > 0 {
            self.persist_requests(next).await?;
        }
        Ok(removed)
    }

    // ---- internals ------------------------------------------------------

    fn entries(&self) -> Arc<Vec<Entry>> {
        Arc::clone(&self.inner.entries.read().expect("inbox lock poisoned"))
    }

    fn requests(&self) -> Arc<Vec<ForwardingRequest>> {
        Arc::clone(&self.inner.requests.read().expect("inbox lock poisoned"))
    }

    fn raw_path(&self, id: &str) -> Result<PathBuf, InboxError> {
        validate_id(id)?;
        Ok(self.inner.dir.join(format!("{id}.eml")))
    }

    async fn persist_entries(&self, next: Vec<Entry>) -> Result<(), InboxError> {
        let path = self.inner.dir.join("index.json");
        let bytes = serde_json::to_vec_pretty(&IndexOnDisk {
            version: CURRENT_SCHEMA_VERSION,
            entries: next.clone(),
        })
        .map_err(|e| InboxError::Io {
            path: path.display().to_string(),
            source: io::Error::other(e),
        })?;
        write_blocking(&path, bytes).await?;
        *self.inner.entries.write().expect("inbox lock poisoned") = Arc::new(next);
        Ok(())
    }

    async fn persist_requests(&self, next: Vec<ForwardingRequest>) -> Result<(), InboxError> {
        let path = self.inner.dir.join("forwarding.json");
        let bytes = serde_json::to_vec_pretty(&ForwardingOnDisk {
            version: CURRENT_SCHEMA_VERSION,
            requests: next.clone(),
        })
        .map_err(|e| InboxError::Io {
            path: path.display().to_string(),
            source: io::Error::other(e),
        })?;
        write_blocking(&path, bytes).await?;
        *self.inner.requests.write().expect("inbox lock poisoned") = Arc::new(next);
        Ok(())
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }
}

async fn write_blocking(path: &Path, bytes: Vec<u8>) -> Result<(), InboxError> {
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_atomic_0600(&p, &bytes))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)))
        .map_err(|source| InboxError::Io {
            path: path.display().to_string(),
            source,
        })
}

/// Ids name files on disk, so only a conservative charset is accepted.
pub fn validate_id(id: &str) -> Result<(), InboxError> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(InboxError::BadId(id.to_string()))
    }
}

fn load_json<T: serde::de::DeserializeOwned + HasVersion>(path: &Path) -> Option<T> {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "inbox: file unreadable; starting empty");
            return None;
        }
    };
    match serde_json::from_str::<T>(&s) {
        Ok(v) if v.version() == CURRENT_SCHEMA_VERSION => Some(v),
        Ok(v) => {
            back_up_corrupt(path, &format!("unknown schema version {}", v.version()));
            None
        }
        Err(e) => {
            back_up_corrupt(path, &e.to_string());
            None
        }
    }
}

trait HasVersion {
    fn version(&self) -> u32;
}

impl HasVersion for IndexOnDisk {
    fn version(&self) -> u32 {
        self.version
    }
}

impl HasVersion for ForwardingOnDisk {
    fn version(&self) -> u32 {
        self.version
    }
}

fn back_up_corrupt(path: &Path, reason: &str) {
    let backup = path.with_extension(format!("json.corrupt.{}", now_unix_secs()));
    if let Err(e) = fs::rename(path, &backup) {
        warn!(path = %path.display(), error = %e, reason, "inbox: corrupt file could not be moved aside; starting empty");
    } else {
        warn!(path = %path.display(), backup = %backup.display(), reason, "inbox: corrupt file backed up; starting empty");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ids(inbox: &Inbox) -> HashSet<String> {
        inbox.entries().iter().map(|e| e.id.clone()).collect()
    }

    pub(crate) fn meta(id: &str, received_at: u64) -> Metadata {
        Metadata {
            id: id.into(),
            kind: p2claw_email_proto::Kind::Message,
            received_at,
            to: "alias@p2claw.com".into(),
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

    const RAW: &[u8] =
        b"From: you@gmail.com\r\nTo: alias@p2claw.com\r\nSubject: hello there\r\n\r\nbody\r\n";

    #[tokio::test]
    async fn store_list_get_raw_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        let mut rx = inbox.subscribe();
        let e = inbox.store_message(&meta("m_1", 100), RAW).await.unwrap();
        assert_eq!(e.subject, "hello there");
        assert_eq!(e.size, RAW.len() as u64);
        assert_eq!(rx.recv().await.unwrap(), "m_1");

        let list = inbox.list(false);
        assert_eq!(list.len(), 1);
        assert_eq!(inbox.raw("m_1").await.unwrap(), RAW);
        assert_eq!(inbox.unread_count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["index.json", "m_1.eml"] {
                let mode = fs::metadata(inbox.dir().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{name}");
            }
        }

        // Reload from disk sees the same row.
        let again = Inbox::load_or_empty(dir.path().join("mail"));
        assert_eq!(again.get("m_1"), Some(e));
    }

    #[tokio::test]
    async fn store_is_idempotent_per_id() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        inbox.store_message(&meta("m_1", 100), RAW).await.unwrap();
        inbox
            .store_message(&meta("m_1", 200), b"other")
            .await
            .unwrap();
        assert_eq!(inbox.list(false).len(), 1);
        assert_eq!(inbox.raw("m_1").await.unwrap(), RAW);
    }

    #[tokio::test]
    async fn ack_keeps_delete_removes() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        inbox.store_message(&meta("m_1", 100), RAW).await.unwrap();
        inbox.store_message(&meta("m_2", 200), RAW).await.unwrap();

        assert!(inbox.ack("m_1").await.unwrap().acked);
        assert_eq!(
            inbox
                .list(true)
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["m_2"]
        );
        assert_eq!(inbox.list(false).len(), 2, "ack does not delete");
        assert_eq!(inbox.unread_count(), 1);

        inbox.delete("m_1").await.unwrap();
        assert!(!inbox.dir().join("m_1.eml").exists());
        assert!(matches!(
            inbox.delete("m_1").await,
            Err(InboxError::NotFound(_))
        ));
        assert!(matches!(
            inbox.ack("m_1").await,
            Err(InboxError::NotFound(_))
        ));
        assert_eq!(ids(&inbox), HashSet::from(["m_2".to_string()]));
    }

    #[tokio::test]
    async fn list_is_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        inbox.store_message(&meta("m_old", 100), RAW).await.unwrap();
        inbox.store_message(&meta("m_new", 300), RAW).await.unwrap();
        inbox
            .record_expired(&Summary {
                id: "m_mid".into(),
                received_at: 200,
                from: "x@y.org".into(),
                subject: "gone".into(),
            })
            .await
            .unwrap();
        let ids: Vec<String> = inbox.list(false).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, ["m_new", "m_mid", "m_old"]);
    }

    #[tokio::test]
    async fn expired_entries_have_no_raw() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        let e = inbox
            .record_expired(&Summary {
                id: "m_x".into(),
                received_at: 5,
                from: "x@y.org".into(),
                subject: "gone".into(),
            })
            .await
            .unwrap();
        assert_eq!(e.kind, EntryKind::Expired);
        assert!(matches!(
            inbox.raw("m_x").await,
            Err(InboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn bad_ids_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        for bad in ["", "../x", "a/b", "a.b", &"x".repeat(65)] {
            let err = inbox.store_message(&meta(bad, 1), RAW).await.unwrap_err();
            assert!(matches!(err, InboxError::BadId(_)), "{bad:?}: {err:?}");
        }
        assert!(matches!(
            inbox.raw("../x").await,
            Err(InboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn forwarding_requests_are_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::load_or_empty(dir.path().join("mail"));
        let req = ForwardingRequest {
            id: "m_f".into(),
            account: Some("acct@gmail.com".into()),
            link: Some("https://mail-settings.google.com/mail/vf-secret".into()),
            received_at: 9,
        };
        inbox.store_forwarding_request(req.clone()).await.unwrap();
        inbox.store_forwarding_request(req.clone()).await.unwrap();
        assert_eq!(inbox.forwarding_requests(), vec![req]);
        assert!(inbox.list(false).is_empty(), "never in the inbox");

        let again = Inbox::load_or_empty(dir.path().join("mail"));
        assert_eq!(again.forwarding_requests().len(), 1);
        assert_eq!(
            again
                .remove_forwarding_requests("acct@gmail.com")
                .await
                .unwrap(),
            1
        );
        assert!(again.forwarding_requests().is_empty());
    }

    #[tokio::test]
    async fn corrupt_index_is_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let mail = dir.path().join("mail");
        fs::create_dir_all(&mail).unwrap();
        fs::write(mail.join("index.json"), b"garbage").unwrap();
        let inbox = Inbox::load_or_empty(mail.clone());
        assert!(inbox.list(false).is_empty());
        let backups = fs::read_dir(&mail)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert_eq!(backups, 1);
    }
}
