//! Route table + atomic on-disk persistence.
//!
//! Written mode `0600` via the same
//! temp-file-then-rename pattern used by `state_store.rs`: the route
//! record doesn't contain secrets, but it gives any reader the set of
//! live apps, and the shared write path has already been audited.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use p2claw_control_proto::AuthMethod;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;
use url::Url;

use crate::validate::{
    validate_app_name, validate_private_upstream, validate_upstream, ValidateError,
};

/// Who may reach a route.
///
/// `Public` is today's behavior: announced to coord, reachable by
/// visitors via edge/browser and by any authenticated peer.
/// `Private` routes are never announced, get no visitor URL, and
/// are served only to peers the route is shared with
/// (`shares.json`). The serde default keeps older `routes.json`
/// files and callers loading unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    #[default]
    Public,
    Private,
}

/// Current on-disk schema version. v3
/// replaces the v2 `requires_auth: bool` with `auth:
/// Vec<AuthMethod>` to match the wire reshape — empty vec is the
/// new "public app", any populated method list means the daemon
/// middleware gates the request. v1 and v2 files are still readable:
/// they load with their legacy field shapes mapped to the v3
/// representation, then get rewritten as v3 on the next mutation.
///
/// v4 is a **downgrade guard**, not a shape change: the payload is
/// identical to v3, and `write_to_disk` stamps v4 ONLY when at least
/// one private route exists (v3 otherwise). `visibility` rides
/// serde-default, so a pre-visibility binary reading the file would
/// load every private route as public and announce its name to
/// coord — and the auto-upgrade watchdog's rollback makes "old
/// binary reads new state" an automated event, not a hypothetical.
/// Stamping v4 makes that read fail closed instead: the old binary
/// refuses the unknown version, backs the file up, and starts empty
/// and degraded, which suppresses the announce entirely. Routes go
/// dark until re-upgrade (recoverable from the backup) — dark beats
/// leaked. Files with only public routes keep stamping v3 so a
/// rollback stays fully functional for everyone not using the
/// feature.
const CURRENT_SCHEMA_VERSION: u32 = 4;
/// Version stamped when every route is public — readable by
/// pre-visibility binaries, keeping rollback harmless for them.
const PUBLIC_ONLY_SCHEMA_VERSION: u32 = 3;
/// Last-known-readable schema (used for the v1 → v2 → v3 migrations).
const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// A registered route. `serde` deserialization does not set
/// `deny_unknown_fields`, so older callers still sending legacy
/// `passthrough_hosts` / `default` or schema-v2 `requires_auth`
/// fields get their request accepted — unknown fields are silently
/// dropped and `requires_auth` is read by `read_from_disk` BEFORE
/// the strict serde deserialize so we don't lose the gate setting
/// on a v2 → v3 migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteRecord {
    pub name: String,
    pub upstream: String,
    /// Unix seconds the agent first accepted this route. Used by coord
    /// to order quota-trimming: oldest registrations win when a peer
    /// is over their `max_apps`.
    /// Defaulted to 0 when missing on-disk so legacy v1 files load
    /// cleanly; `read_from_disk` backfills with the file mtime.
    #[serde(default)]
    pub registered_at: u64,
    /// Per-app
    /// authentication method list. Empty vec = public app — the
    /// daemon middleware still strips inbound `X-P2claw-*` headers
    /// (defense-in-depth) but forwards without a credential check.
    /// Any populated entry triggers the middleware to iterate the
    /// list; first method to validate forwards with identity
    /// headers, no match returns 401 + `P2claw-Auth-Required: true`.
    ///
    /// Sources of truth:
    ///
    /// 1. Operator-set via `p2claw apps expose <name> --port <p>
    ///    [--auth-oauth [providers]]` (the local-API register-app
    ///    body carries this as the `auth` field).
    /// 2. Coord-pushed via the control-channel app-sync
    ///    (`RouteAnnounceAck.accepted_apps[].auth`); agent updates
    ///    local persistence to converge on coord's view.
    ///
    /// `serde(default)` means legacy v3 records without the field
    /// load as empty (public app). v2 records with `requires_auth`
    /// are migrated at `read_from_disk` time — the bool is mapped
    /// onto the new shape (`true → vec![AuthMethod::oauth_any()]`,
    /// `false → vec![]`) before the v3 file is rewritten.
    #[serde(default)]
    pub auth: Vec<AuthMethod>,
    /// Route class. Rides the same serde-default discipline as
    /// `auth`: absent on-disk / on-wire means `public`, so no
    /// schema bump.
    #[serde(default)]
    pub visibility: Visibility,
    /// Lazily-parsed `upstream`, primed at load/registration so
    /// per-request callers never re-parse. Clones carry the primed
    /// value. Excluded from serde and equality.
    #[serde(skip)]
    pub upstream_parsed: OnceLock<Url>,
}

impl PartialEq for RouteRecord {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.upstream == other.upstream
            && self.registered_at == other.registered_at
            && self.auth == other.auth
            && self.visibility == other.visibility
    }
}

impl Eq for RouteRecord {}

impl RouteRecord {
    /// True iff the app should be served without authentication.
    /// Mirrors the legacy `!requires_auth` predicate but reads
    /// off the new method list. Helper because three or four
    /// call sites otherwise need to spell out
    /// `self.auth.is_empty()` and the named predicate reads better.
    pub fn is_public(&self) -> bool {
        self.auth.is_empty()
    }

    /// True iff the route is private-visibility (shared peers
    /// only). Distinct from [`is_public`], which is about the
    /// *auth gate* on a visitor-reachable route.
    ///
    /// [`is_public`]: RouteRecord::is_public
    pub fn is_private(&self) -> bool {
        self.visibility == Visibility::Private
    }
}

impl RouteRecord {
    /// The parsed upstream URL. Parsed at most once per record;
    /// load/registration prime the cache so hot-path callers get a
    /// plain field read.
    pub fn upstream_url(&self) -> &Url {
        self.upstream_parsed.get_or_init(|| {
            // Validated at insert time; this parse is infallible in
            // practice but we don't want to panic on a corrupted
            // on-disk file either — return an obviously-dead URL.
            Url::parse(&self.upstream).unwrap_or_else(|_| {
                Url::parse("http://127.0.0.1:0").expect("static url always parses")
            })
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    routes: Vec<RouteRecord>,
}

/// Permissive on-disk row shape used during `read_from_disk` to
/// migrate v2 records (with `requires_auth: bool`) into the v3
/// `auth: Vec<AuthMethod>` representation. Both legacy and current
/// auth fields are optional so a v1 file (neither field), a v2
/// file (`requires_auth` set), or a v3 file (`auth` set) all parse
/// cleanly; `normalize` picks the right source and produces a
/// `RouteRecord` with the v3 shape. Writing always uses the
/// `RouteRecord` shape directly — no read-through here.
#[derive(Debug, Deserialize)]
struct OnDiskRoute {
    name: String,
    upstream: String,
    #[serde(default)]
    registered_at: u64,
    /// v3 field: present on v3 files written by current agents.
    #[serde(default)]
    auth: Option<Vec<AuthMethod>>,
    /// v2 field: present on files written by legacy agents that
    /// haven't been rewritten as v3 yet. Migrated to `auth` per
    /// the bool → method-list mapping in `normalize`. Current
    /// daemons never emit this field on write; reading it is
    /// purely for the migration window.
    #[serde(default)]
    requires_auth: Option<bool>,
    /// Route class; absent on files written before visibility
    /// existed → `public`.
    #[serde(default)]
    visibility: Visibility,
}

impl OnDiskRoute {
    /// Map the permissive on-disk shape onto a v3 `RouteRecord`.
    /// Precedence: explicit `auth` wins over derived-from-
    /// `requires_auth` (so a v3-bumped record never silently
    /// loses its method list just because someone hand-edited the
    /// file to add a stray `requires_auth: false`). Absence of
    /// both → public (empty `auth`).
    fn normalize(self) -> RouteRecord {
        let auth = match (self.auth, self.requires_auth) {
            (Some(a), _) => a,
            (None, Some(true)) => vec![AuthMethod::oauth_any()],
            (None, Some(false)) | (None, None) => Vec::new(),
        };
        RouteRecord {
            name: self.name,
            upstream: self.upstream,
            registered_at: self.registered_at,
            auth,
            visibility: self.visibility,
            upstream_parsed: OnceLock::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OnDiskRaw {
    version: u32,
    routes: Vec<OnDiskRoute>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Validate(#[from] ValidateError),
    #[error("route `{0}` is not registered")]
    NotFound(String),
    #[error("refuse to read routes.json with unknown schema version {0}")]
    UnknownSchemaVersion(u32),
}

/// In-memory route table. Readers (`get`/`list`, called per request)
/// take an `Arc` snapshot from an `RwLock` that is only ever held for
/// the swap; mutations build a new snapshot, swap it in, then persist
/// on the blocking pool. A separate async mutex serializes the
/// mutate→persist ordering so concurrent writers can't interleave
/// their disk writes.
///
/// Cloning is `Arc`-cheap — all callers share one instance.
#[derive(Clone)]
pub struct RouteTable {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    /// Reader-visible snapshot, replaced whole on mutation so reads
    /// never contend with persistence.
    routes: RwLock<Arc<Vec<RouteRecord>>>,
    /// Serializes mutation + persist across writers. Never held by
    /// readers.
    write_lock: Mutex<()>,
    /// True when the initial on-disk load did NOT cleanly parse a
    /// routes file — i.e. the file was absent (`Missing`) or
    /// unreadable (`CorruptRecovered`). The in-memory table is empty
    /// in both cases, but that emptiness is *unverified*: it may
    /// reflect lost/damaged state rather than a genuine "no routes"
    /// intent. Consumers that broadcast the route set as an
    /// authoritative snapshot (the control connection's post-hello
    /// `route_announce`) consult this to avoid asserting an empty set
    /// coord would treat as "delete all my apps". Cleared by the
    /// first successful write (`upsert`/`remove`), after which the
    /// table reflects a real, operator-driven state.
    degraded_load: AtomicBool,
}

impl RouteTable {
    /// Load from `path`, or start empty if missing. On corruption,
    /// back the file up and begin with an empty table.
    pub fn load_or_empty(path: PathBuf) -> Self {
        // `degraded` = the empty table is *unverified*: the file was
        // absent or unreadable, so we can't tell "no routes" from
        // "lost routes". A clean parse (including a valid empty file)
        // is NOT degraded — an operator who unexposed everything
        // leaves a present, valid `[]` on disk.
        let (routes, degraded) = match read_from_disk(&path) {
            Ok(v) => (v, false),
            Err(ReadError::Missing) => (Vec::new(), true),
            Err(ReadError::Corrupt(reason)) => {
                let backup = corrupt_backup_path(&path);
                if let Err(e) = fs::rename(&path, &backup) {
                    warn!(
                        path = %path.display(),
                        backup = %backup.display(),
                        error = %e,
                        reason = %reason,
                        "routes.json unreadable; could not move it aside — starting empty anyway"
                    );
                } else {
                    warn!(
                        path = %path.display(),
                        backup = %backup.display(),
                        reason = %reason,
                        "routes.json corrupt; backed up and starting empty"
                    );
                }
                (Vec::new(), true)
            }
        };
        Self {
            inner: Arc::new(Inner {
                path,
                routes: RwLock::new(Arc::new(routes)),
                write_lock: Mutex::new(()),
                degraded_load: AtomicBool::new(degraded),
            }),
        }
    }

    /// Whether the initial load left the table in an *unverified*
    /// empty state (file absent or corrupt). Consumers that
    /// authoritatively broadcast the route set — the control
    /// connection's post-hello `route_announce` — check this and skip
    /// announcing an empty snapshot in this state, so a transient
    /// load failure can't be read by coord as "delete all my apps".
    /// Cleared by the first successful `upsert`/`remove`, after which
    /// the table reflects a real operator-driven state.
    pub fn initial_load_degraded(&self) -> bool {
        self.inner.degraded_load.load(Ordering::Acquire)
    }

    /// Snapshot the current route set.
    pub async fn list(&self) -> Vec<RouteRecord> {
        self.snapshot().as_ref().clone()
    }

    /// Fetch a single route by name.
    pub async fn get(&self, name: &str) -> Option<RouteRecord> {
        self.snapshot().iter().find(|r| r.name == name).cloned()
    }

    fn snapshot(&self) -> Arc<Vec<RouteRecord>> {
        Arc::clone(&self.inner.routes.read().expect("routes lock poisoned"))
    }

    /// Swap `snapshot` in for readers, then persist it on the
    /// blocking pool. Caller must hold `write_lock` so writes hit
    /// the disk in mutation order. A successful write means the
    /// table now reflects real, operator-driven state — the
    /// initial-load emptiness (if any) is no longer "unverified".
    async fn swap_and_persist(&self, snapshot: Arc<Vec<RouteRecord>>) -> Result<(), RouteError> {
        *self.inner.routes.write().expect("routes lock poisoned") = Arc::clone(&snapshot);
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || write_to_disk(&path, &snapshot))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)))
            .map_err(|source| RouteError::Io {
                path: self.inner.path.display().to_string(),
                source,
            })?;
        self.inner.degraded_load.store(false, Ordering::Release);
        Ok(())
    }

    /// Insert or replace a route. Validates inputs and persists to
    /// disk on success. If the caller didn't supply a
    /// `registered_at` (it's the default `0`), we stamp `now()` for
    /// new records and preserve the existing timestamp on replace —
    /// keeping the "oldest first" ordering coord uses for quota
    /// trimming stable across
    /// upstream-port rewrites.
    pub async fn upsert(&self, mut record: RouteRecord) -> Result<RouteRecord, RouteError> {
        validate_app_name(&record.name)?;
        // Private routes additionally accept `unix:` upstreams;
        // public routes keep the loopback-TCP-only rule.
        let _upstream_url = match record.visibility {
            Visibility::Private => validate_private_upstream(&record.upstream)?,
            Visibility::Public => validate_upstream(&record.upstream)?,
        };
        // Private + auth is contradictory — the forwarder's private
        // branch never consults auth methods (shares are the only
        // gate), so accepting the combination would silently ignore
        // the methods. The CLI already blocks it; reject it here so
        // raw API callers get the same answer.
        if record.visibility == Visibility::Private && !record.auth.is_empty() {
            return Err(ValidateError::PrivateWithAuth.into());
        }
        // Prime the parsed-URL cache so every clone handed out by
        // `get` carries it.
        let _ = record.upstream_url();

        let _write = self.inner.write_lock.lock().await;
        let mut next = self.snapshot().as_ref().clone();
        if let Some(existing) = next.iter_mut().find(|r| r.name == record.name) {
            // Replace-in-place: keep the original registered_at so the
            // route's quota-ordering "age" doesn't reset on every
            // upstream-port change.
            if record.registered_at == 0 {
                record.registered_at = existing.registered_at;
            }
            *existing = record.clone();
        } else {
            if record.registered_at == 0 {
                record.registered_at = now_unix_secs();
            }
            next.push(record.clone());
        }

        self.swap_and_persist(Arc::new(next)).await?;
        Ok(record)
    }

    /// Remove a route by name. `Ok(())` on success, `NotFound` if
    /// `name` isn't registered.
    pub async fn remove(&self, name: &str) -> Result<(), RouteError> {
        let _write = self.inner.write_lock.lock().await;
        let mut next = self.snapshot().as_ref().clone();
        let before = next.len();
        next.retain(|r| r.name != name);
        if next.len() == before {
            return Err(RouteError::NotFound(name.to_string()));
        }
        // A successful write (even down to an empty set) is an
        // explicit operator action — the emptiness is now verified,
        // so subsequent announces may legitimately assert it.
        self.swap_and_persist(Arc::new(next)).await
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

/// Outcome of parsing an on-disk `routes.json`.
enum ReadError {
    Missing,
    Corrupt(String),
}

fn read_from_disk(path: &Path) -> Result<Vec<RouteRecord>, ReadError> {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Corrupt(e.to_string())),
    };
    // Deserialize via the permissive raw shape (both `requires_auth`
    // and `auth` fields are optional) so v1, v2, v3 files all parse
    // cleanly. `OnDiskRoute::normalize` maps each row onto the v3
    // `RouteRecord` shape before the rest of the load path sees it.
    let parsed: OnDiskRaw = match serde_json::from_str(&s) {
        Ok(v) => v,
        Err(e) => return Err(ReadError::Corrupt(e.to_string())),
    };
    // Accept v1, v2 (legacy `requires_auth`), and v3 (current).
    // Anything else (truly old or future) is corruption.
    if parsed.version > CURRENT_SCHEMA_VERSION || parsed.version < MIN_SUPPORTED_SCHEMA_VERSION {
        return Err(ReadError::Corrupt(format!(
            "unknown schema version {}",
            parsed.version
        )));
    }
    let backfill_ts = if parsed.version < CURRENT_SCHEMA_VERSION {
        file_mtime_unix_secs(path).unwrap_or_else(now_unix_secs)
    } else {
        0
    };
    // Filter out any record that no longer validates — the on-disk
    // file might carry a route whose upstream host has changed
    // resolution since last start (e.g. `/etc/hosts` updated). Prefer
    // dropping the offender to refusing the whole table.
    //
    // Validation here is name syntax + upstream parseability only.
    // The upstream loopback check happens at registration time and at
    // forward time, so we keep the record (the forward-time dial
    // re-check catches resolution drift).
    let mut out = Vec::with_capacity(parsed.routes.len());
    for raw in parsed.routes {
        if let Err(e) = validate_app_name(&raw.name) {
            warn!(name = %raw.name, error = %e, "routes.json: dropping route with invalid name");
            continue;
        }
        if Url::parse(&raw.upstream).is_err() {
            warn!(name = %raw.name, upstream = %raw.upstream, "routes.json: dropping route with unparseable upstream");
            continue;
        }
        let mut r = raw.normalize();
        if r.registered_at == 0 && backfill_ts != 0 {
            r.registered_at = backfill_ts;
        }
        // Prime the parsed-URL cache so per-request clones carry it.
        let _ = r.upstream_url();
        out.push(r);
    }
    Ok(out)
}

fn file_mtime_unix_secs(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_to_disk(path: &Path, routes: &[RouteRecord]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Downgrade guard: stamp v4 only when a private route exists so a
    // pre-visibility binary refuses the file (fail closed) instead of
    // loading private routes as public. All-public files stay v3.
    let version = if routes.iter().any(|r| r.visibility == Visibility::Private) {
        CURRENT_SCHEMA_VERSION
    } else {
        PUBLIC_ONLY_SCHEMA_VERSION
    };
    let payload = OnDisk {
        version,
        routes: routes.to_vec(),
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
    let ts = now_unix_secs();
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

    fn rec(name: &str, upstream: &str) -> RouteRecord {
        RouteRecord {
            name: name.into(),
            upstream: upstream.into(),
            ..Default::default()
        }
    }

    fn private_rec(name: &str, upstream: &str) -> RouteRecord {
        RouteRecord {
            visibility: Visibility::Private,
            ..rec(name, upstream)
        }
    }

    /// v2 routes.json (with `requires_auth: true`) loads as a
    /// v3 record carrying `auth: [{kind:"oauth"}]`. Round-tripped
    /// once → file rewritten as v3 on the next mutation.
    #[tokio::test]
    async fn legacy_v2_requires_auth_migrates_to_oauth_method_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        // Hand-craft a v2 file as it would have been written by
        // legacy v2 agents.
        let v2 = serde_json::json!({
            "version": 2,
            "routes": [{
                "name": "gated",
                "upstream": "http://127.0.0.1:5173",
                "registered_at": 1_700_000_000u64,
                "requires_auth": true,
            }, {
                "name": "public",
                "upstream": "http://127.0.0.1:5174",
                "registered_at": 1_700_000_001u64,
                "requires_auth": false,
            }],
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&v2).unwrap()).unwrap();

        let t = RouteTable::load_or_empty(path.clone());
        let list = t.list().await;
        let gated = list.iter().find(|r| r.name == "gated").unwrap();
        assert_eq!(gated.auth, vec![AuthMethod::oauth_any()]);
        assert!(!gated.is_public());
        let public = list.iter().find(|r| r.name == "public").unwrap();
        assert!(public.is_public());

        // Trigger a write (upsert a third route) so the file is
        // rewritten as v3; verify the on-disk shape.
        t.upsert(rec("extra", "http://127.0.0.1:5175"))
            .await
            .unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["version"], 3);
        // No `requires_auth` field on any rewritten record.
        for r in written["routes"].as_array().unwrap() {
            assert!(
                !r.as_object().unwrap().contains_key("requires_auth"),
                "v3 file must not carry legacy `requires_auth`: {r}"
            );
        }
        // Gated app round-tripped via the new `auth` field.
        let gated_written = written["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "gated")
            .unwrap();
        assert_eq!(gated_written["auth"], serde_json::json!([{"kind":"oauth"}]));
    }

    /// v3 records with `auth` explicit beat any stray
    /// `requires_auth` field (forward-compat: a hand-edited file
    /// that has BOTH must not silently lose the method list).
    #[tokio::test]
    async fn v3_auth_field_beats_legacy_requires_auth_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let mixed = serde_json::json!({
            "version": 3,
            "routes": [{
                "name": "honor-auth",
                "upstream": "http://127.0.0.1:5173",
                "registered_at": 1,
                "auth": [{"kind":"oauth","providers":["github"]}],
                "requires_auth": false,  // stray; must be ignored.
            }],
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&mixed).unwrap()).unwrap();
        let t = RouteTable::load_or_empty(path);
        let list = t.list().await;
        let r = &list[0];
        assert_eq!(
            r.auth,
            vec![AuthMethod::oauth_with(vec!["github".into()])],
            "explicit `auth` must win over stray `requires_auth`"
        );
    }

    /// `visibility` deserializes to `Public` when absent — both from
    /// caller payloads and from pre-visibility on-disk files.
    #[test]
    fn visibility_defaults_to_public_on_deserialize() {
        let r: RouteRecord =
            serde_json::from_str(r#"{"name":"a","upstream":"http://127.0.0.1:1"}"#).unwrap();
        assert_eq!(r.visibility, Visibility::Public);
        assert!(!r.is_private());
    }

    /// Private routes round-trip through the on-disk file, including
    /// a `unix:` upstream; public records written by this version
    /// carry an explicit `"visibility":"public"`.
    #[tokio::test]
    async fn private_route_roundtrips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path.clone());
        t.upsert(private_rec("mysvc", "unix:/run/user/1000/mysvc.sock"))
            .await
            .unwrap();
        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();

        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let routes = raw["routes"].as_array().unwrap();
        let mysvc = routes.iter().find(|r| r["name"] == "mysvc").unwrap();
        assert_eq!(mysvc["visibility"], "private");
        let recipes = routes.iter().find(|r| r["name"] == "recipes").unwrap();
        assert_eq!(recipes["visibility"], "public");

        let t2 = RouteTable::load_or_empty(path);
        let got = t2.get("mysvc").await.unwrap();
        assert!(got.is_private());
        assert_eq!(got.upstream, "unix:/run/user/1000/mysvc.sock");
    }

    /// Downgrade guard: a file containing any private route is
    /// stamped v4 (a pre-visibility binary refuses it, fails closed,
    /// and never announces the private name); an all-public file
    /// stays v3 so a rollback remains fully functional without the
    /// feature.
    #[tokio::test]
    async fn private_route_stamps_v4_public_only_stays_v3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path.clone());

        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 3, "all-public file must stay v3");

        t.upsert(private_rec("mysvc", "unix:/run/user/1000/mysvc.sock"))
            .await
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 4, "file with a private route must stamp v4");

        // Removing the private route drops the stamp back to v3.
        t.remove("mysvc").await.unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            raw["version"], 3,
            "back to v3 once no private routes remain"
        );
    }

    /// Private routes cannot carry auth methods — the private branch
    /// never consults them (shares are the only gate), so accepting
    /// the combination would silently ignore the methods.
    #[tokio::test]
    async fn private_route_with_auth_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let mut r = private_rec("mysvc", "unix:/run/user/1000/mysvc.sock");
        r.auth = vec![AuthMethod::oauth_any()];
        let err = t.upsert(r).await.unwrap_err();
        assert!(
            matches!(err, RouteError::Validate(ValidateError::PrivateWithAuth)),
            "got {err:?}"
        );
    }

    /// A v3 file with no `visibility` fields (written by an older
    /// agent) loads with every route public.
    #[tokio::test]
    async fn pre_visibility_v3_file_loads_as_public() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        fs::write(
            &path,
            br#"{
                "version":3,
                "routes":[{
                    "name":"recipes",
                    "upstream":"http://127.0.0.1:5173",
                    "registered_at":1700000000,
                    "auth":[]
                }]
            }"#,
        )
        .unwrap();
        let t = RouteTable::load_or_empty(path);
        let got = t.get("recipes").await.unwrap();
        assert_eq!(got.visibility, Visibility::Public);
    }

    #[tokio::test]
    async fn upsert_rejects_unix_upstream_on_public_route() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let err = t
            .upsert(rec("mysvc", "unix:/run/user/1000/mysvc.sock"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                RouteError::Validate(ValidateError::UpstreamUnixNotAllowed)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn upsert_accepts_unix_upstream_on_private_route() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        t.upsert(private_rec("mysvc", "unix:/run/user/1000/mysvc.sock"))
            .await
            .unwrap();
        assert!(t.get("mysvc").await.unwrap().is_private());
    }

    #[tokio::test]
    async fn upsert_rejects_relative_unix_upstream_on_private_route() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let err = t
            .upsert(private_rec("mysvc", "unix:mysvc.sock"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                RouteError::Validate(ValidateError::UpstreamUnixNotAbsolute(_))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn load_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        assert!(t.list().await.is_empty());
    }

    #[tokio::test]
    async fn upsert_persists_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path.clone());
        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();

        // File exists and is mode 0600.
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Fresh load sees the route.
        let t2 = RouteTable::load_or_empty(path);
        let got = t2.list().await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "recipes");
        assert!(
            got[0].registered_at > 0,
            "new routes get an autostamped registered_at"
        );
    }

    #[tokio::test]
    async fn corrupt_file_is_backed_up_and_table_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        fs::write(&path, b"not json at all").unwrap();

        let t = RouteTable::load_or_empty(path.clone());
        assert!(t.list().await.is_empty());

        // Backup exists somewhere in the dir.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
            .collect();
        let backup_count = entries
            .iter()
            .filter(|n| n.starts_with("routes.json.corrupt."))
            .count();
        assert_eq!(backup_count, 1, "entries: {entries:?}");
    }

    // ---- degraded-load tracking ------------------------------------
    //
    // The post-hello `route_announce` is an authoritative snapshot;
    // coord deletes any app the box omits. An *unverified*-empty
    // table (routes.json absent/corrupt) must not be announced as
    // "no apps", or coord wipes the box's registrations. These tests
    // pin which load states are flagged degraded and that the first
    // successful write clears the flag.

    #[tokio::test]
    async fn missing_file_marks_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        assert!(t.list().await.is_empty());
        assert!(
            t.initial_load_degraded(),
            "absent routes.json is unverified-empty → degraded"
        );
    }

    #[tokio::test]
    async fn corrupt_file_marks_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        fs::write(&path, b"not json at all").unwrap();
        let t = RouteTable::load_or_empty(path);
        assert!(t.list().await.is_empty());
        assert!(
            t.initial_load_degraded(),
            "corrupt routes.json is unverified-empty → degraded"
        );
    }

    #[tokio::test]
    async fn present_valid_empty_file_is_not_degraded() {
        // An operator who unexposed everything leaves a present,
        // valid `[]` — a *verified* empty set, safe to announce.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        // Write a genuine empty table via the same on-disk path.
        write_to_disk(&path, &[]).unwrap();
        let t = RouteTable::load_or_empty(path);
        assert!(t.list().await.is_empty());
        assert!(
            !t.initial_load_degraded(),
            "present valid empty file is a verified-empty set → NOT degraded"
        );
    }

    #[tokio::test]
    async fn present_valid_nonempty_file_is_not_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let seed = RouteTable::load_or_empty(path.clone());
        seed.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();
        // Reload from the now-populated file.
        let t = RouteTable::load_or_empty(path);
        assert_eq!(t.list().await.len(), 1);
        assert!(!t.initial_load_degraded());
    }

    #[tokio::test]
    async fn first_successful_upsert_clears_degraded() {
        let dir = tempfile::tempdir().unwrap();
        // Absent file → degraded.
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        assert!(t.initial_load_degraded());
        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();
        assert!(
            !t.initial_load_degraded(),
            "a successful write is a verified state → degraded cleared"
        );
    }

    #[tokio::test]
    async fn successful_remove_to_empty_clears_degraded() {
        // Seed one route into a fresh (degraded) table, then remove
        // it. The table is empty again but now *verified* empty — the
        // operator explicitly removed the last app — so degraded is
        // cleared and a subsequent empty announce is legitimate.
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        assert!(t.initial_load_degraded());
        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();
        t.remove("recipes").await.unwrap();
        assert!(t.list().await.is_empty());
        assert!(
            !t.initial_load_degraded(),
            "explicit removal to empty is verified-empty → NOT degraded"
        );
    }

    #[tokio::test]
    async fn upsert_replaces_existing_route_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        t.upsert(rec("recipes", "http://127.0.0.1:5173"))
            .await
            .unwrap();
        let first = t.list().await[0].clone();
        // Tiny gap to ensure now() advances; doesn't matter for the
        // assertion (we check inequality below) but makes intent clear.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        t.upsert(rec("recipes", "http://127.0.0.1:6000"))
            .await
            .unwrap();

        let got = t.list().await;
        assert_eq!(got.len(), 1, "no duplicate rows on replace");
        assert_eq!(got[0].upstream, "http://127.0.0.1:6000");
        assert_eq!(
            got[0].registered_at, first.registered_at,
            "registered_at must survive an upstream-port rewrite"
        );
    }

    #[tokio::test]
    async fn upsert_rejects_reserved_name() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let err = t
            .upsert(rec("admin", "http://127.0.0.1:5173"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RouteError::Validate(ValidateError::ReservedAppName(_))),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn upsert_rejects_non_loopback_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let err = t.upsert(rec("bad", "http://8.8.8.8:80")).await.unwrap_err();
        assert!(
            matches!(
                err,
                RouteError::Validate(ValidateError::UpstreamNonLoopback(_, _))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn upsert_accepts_payload_with_unknown_fields() {
        // Legacy callers still send `passthrough_hosts` and `default`;
        // serde on `RouteRecord` doesn't `deny_unknown_fields`, so the
        // fields are silently dropped on deserialize and the route
        // registers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path);
        let payload = br#"{
            "name":"legacy",
            "upstream":"http://127.0.0.1:5173",
            "passthrough_hosts":["fonts.googleapis.com"],
            "default":false
        }"#;
        let parsed: RouteRecord =
            serde_json::from_slice(payload).expect("unknown fields must be ignored");
        t.upsert(parsed).await.expect("upsert must succeed");
        let got = t.list().await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "legacy");
    }

    #[tokio::test]
    async fn on_disk_v1_file_with_legacy_fields_loads_and_migrates() {
        // A v1 routes.json carries `passthrough_hosts` AND `default`
        // AND no `registered_at`. Loading must succeed (no
        // `.corrupt.` backup), drop the legacy fields, and synthesize
        // a `registered_at` from the file mtime.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        fs::write(
            &path,
            br#"{
                "version":1,
                "routes":[{
                    "name":"legacy",
                    "upstream":"http://127.0.0.1:5173",
                    "passthrough_hosts":["fonts.googleapis.com","*.example.com"],
                    "default":false
                }]
            }"#,
        )
        .unwrap();
        let t = RouteTable::load_or_empty(path.clone());
        let got = t.list().await;
        assert_eq!(got.len(), 1, "legacy record must survive load");
        assert_eq!(got[0].name, "legacy");
        assert!(
            got[0].registered_at > 0,
            "registered_at should be backfilled from file mtime"
        );
        // No `.corrupt.` sibling — the load was a clean accept.
        let siblings: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
            .filter(|n| n.contains(".corrupt."))
            .collect();
        assert!(
            siblings.is_empty(),
            "unexpected corrupt backup: {siblings:?}"
        );

        // Mutate to trigger a v3 rewrite, then reload and
        // check the current version was persisted.
        t.upsert(rec("recipes", "http://127.0.0.1:5174"))
            .await
            .unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"version\": 3"),
            "expected v3 after upsert, got:\n{raw}"
        );
        assert!(
            !raw.contains("passthrough_hosts") && !raw.contains("\"default\""),
            "rewrite must drop legacy v1 fields:\n{raw}"
        );
        assert!(
            !raw.contains("requires_auth"),
            "v3 rewrite must drop legacy v2 `requires_auth` field:\n{raw}"
        );
    }

    #[tokio::test]
    async fn remove_deletes_and_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path.clone());
        t.upsert(rec("a", "http://127.0.0.1:5173")).await.unwrap();
        t.remove("a").await.unwrap();
        assert!(t.list().await.is_empty());
        let reloaded = RouteTable::load_or_empty(path);
        assert!(reloaded.list().await.is_empty());
    }

    #[tokio::test]
    async fn remove_404_on_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let t = RouteTable::load_or_empty(dir.path().join("routes.json"));
        let err = t.remove("ghost").await.unwrap_err();
        assert!(matches!(err, RouteError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn atomic_write_does_not_leave_stale_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        let t = RouteTable::load_or_empty(path.clone());
        t.upsert(rec("a", "http://127.0.0.1:5173")).await.unwrap();
        // After the rename, the `.tmp` file should be gone.
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "temp file {tmp:?} leaked");
    }

    #[tokio::test]
    async fn future_schema_version_is_treated_as_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        // Manually write a future-versioned file.
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": 999,
                "routes": [],
            }))
            .unwrap(),
        )
        .unwrap();

        let t = RouteTable::load_or_empty(path);
        // Start empty (file moved to .corrupt).
        assert!(t.list().await.is_empty());
    }
}
