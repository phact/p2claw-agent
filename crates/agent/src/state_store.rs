//! Persistent registration state.
//!
//! Stores the subset of the `POST /v1/register` response the agent
//! needs on subsequent runs: the coord-issued bearer token, the
//! assigned alias, and the coordination / parent domains it was
//! registered against.
//!
//! File presence is the only thing this file claims: "registration
//! completed at some point in the past." It does NOT claim the
//! agent process is alive, that the control-WS is up, or that
//! signaling pushes will reach the box. Those are runtime
//! questions the file can never honestly answer (an earlier
//! attempt at `status: connecting | online` was reverted because
//! the field lies on hard crash). For:
//!
//! - **Real-time online** (control WS currently up): ask coord at
//!   `/internal/alias/<alias>` — coord is the source of truth.
//! - **Process liveness**: use systemd/launchd, or the local-API
//!   socket (a dead process can't answer it).
//! - **Has the agent finished registering this run?**: the local
//!   API's `GET /v1/identity` returns `registered: bool`, derived
//!   from in-process state — race-free, dies with the process.
//!
//! Written atomically: temp-file + fsync + rename, mode `0600` on
//! Unix — same handling as the identity key, since the control_token
//! is a bearer credential.

use std::fs;
use std::io;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine as _;
use p2claw_identity::PeerId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("could not parse agent.state json: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentState {
    pub alias: String,
    pub coord_domain: String,
    pub parent_domain: String,
    /// Coord's root pubkey, persisted as base64url-no-pad on disk
    /// for human-readability in `agent.state`. Same key the
    /// bootstrap pins for binding-sig verification. Used as the
    /// Iroh `NodeID` the agent dials for the control plane. Stable
    /// forever — coord-key rotation is not supported.
    ///
    /// `#[serde(default)]` so legacy on-disk `agent.state`
    /// files without the field still load — the default `PeerId`
    /// is all-zeros which is a recognizable sentinel; coord_conn
    /// would refuse to dial it. Re-register (which produces a
    /// fresh response with the field set) fixes such legacy files
    /// in place.
    #[serde(
        rename = "coord_root_pubkey_b64url",
        serialize_with = "serialize_peer_id_b64url",
        deserialize_with = "deserialize_peer_id_b64url",
        default = "zero_peer_id"
    )]
    pub coord_root_pubkey: PeerId,
    /// Coord's iroh relay URL captured at registration time.
    /// `Option<String>` because production coord typically rides
    /// on a public relay and self-hosted setups may have none.
    /// Persisted so coord_conn can dial without re-issuing
    /// /v1/register on every reconnect.
    ///
    /// `#[serde(default)]` for backward compat: legacy
    /// `agent.state` files without this field load with `None`,
    /// and hermetic-direct-only-mode dials will keep failing for
    /// them until re-registration refreshes the value (which
    /// happens on coord_conn auth-fail loop, so it self-heals
    /// within a few reconnect cycles).
    #[serde(default)]
    pub coord_iroh_relay_url: Option<String>,
    /// Coord's iroh direct addresses (publicly reachable
    /// `ip:port` pairs) captured at registration time. Required
    /// for hermetic mode (relay-disabled) where Iroh has no
    /// other discovery path. Empty vec for backward compat with
    /// older `agent.state` files; a hermetic dial against an
    /// empty addrs list errors with `No addressing information
    /// available` (the bug-of-record this field is here to fix).
    #[serde(default)]
    pub coord_iroh_direct_addrs: Vec<String>,
}

/// Sentinel default for the `coord_root_pubkey` field — see the
/// `#[serde(default)]` docstring above. All-zeros is never a real
/// pubkey emitted by coord; the dial site treats it as a "must
/// re-register" signal.
fn zero_peer_id() -> PeerId {
    PeerId::from_bytes([0u8; 32])
}

fn serialize_peer_id_b64url<S: Serializer>(p: &PeerId, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&B64_URL.encode(p.as_bytes()))
}

fn deserialize_peer_id_b64url<'de, D: Deserializer<'de>>(d: D) -> Result<PeerId, D::Error> {
    use serde::de::Error;
    let raw = String::deserialize(d)?;
    let bytes = B64_URL
        .decode(&raw)
        .map_err(|e| D::Error::custom(format!("base64: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| D::Error::custom(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(PeerId::from_bytes(arr))
}

/// Load state from `path`, or `Ok(None)` if the file does not yet
/// exist (a first-run / post-reset indicator).
pub fn load(path: &Path) -> Result<Option<AgentState>, StateError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StateError::Io {
            path: path.display().to_string(),
            source: e,
        }),
    }
}

/// Atomically persist `state` to `path`. Creates the parent directory
/// if it doesn't exist.
pub fn save(path: &Path, state: &AgentState) -> Result<(), StateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| StateError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    let payload = serde_json::to_vec_pretty(state)?;
    let tmp = temp_path(path);
    write_file_0600(&tmp, &payload)?;
    fs::rename(&tmp, path).map_err(|e| StateError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

fn temp_path(path: &Path) -> std::path::PathBuf {
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

#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| StateError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    f.write_all(bytes).map_err(|e| StateError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    f.sync_all().map_err(|e| StateError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    fs::write(path, bytes).map_err(|e| StateError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentState {
        AgentState {
            alias: "y9abcdefghijk".into(),
            coord_domain: "coord.p2claw.com".into(),
            parent_domain: "p2claw.com".into(),
            // Recognizable non-zero so the roundtrip-on-disk test
            // exercises the b64url codec rather than the all-zero
            // sentinel default.
            coord_root_pubkey: PeerId::from_bytes([0xAB; 32]),
            // Persisted coord-side iroh addressing for hermetic-mode
            // dials. Sample uses Some(_) + a non-empty vec so the
            // on-disk-shape test covers the populated branch.
            coord_iroh_relay_url: Some("https://relay.example.net/".to_string()),
            coord_iroh_direct_addrs: vec!["127.0.0.1:55001".to_string()],
        }
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        let got = load(&p).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        let s = sample();
        save(&p, &s).unwrap();
        let got = load(&p).unwrap().expect("state must be present");
        assert_eq!(got, s);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        save(&p, &sample()).unwrap();
        let mode = fs::metadata(&p).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nested/deep/agent.state");
        save(&p, &sample()).unwrap();
        assert!(p.exists());
    }

    /// JSON-on-disk shape: the registration fields + the coord
    /// pubkey. No bearer token — the control plane authenticates
    /// via Iroh QUIC's TLS handshake against `coord_root_pubkey`,
    /// so a separate bearer is redundant.
    #[test]
    fn on_disk_shape_is_just_registration_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        save(&p, &sample()).unwrap();
        let raw = fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let obj = v.as_object().expect("agent.state must be a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "alias",
                "coord_domain",
                "coord_iroh_direct_addrs",
                "coord_iroh_relay_url",
                "coord_root_pubkey_b64url",
                "parent_domain",
            ],
            "unexpected keys on disk: {keys:?}"
        );
    }

    #[test]
    fn on_disk_legacy_state_loads_with_defaulted_iroh_addr_fields() {
        // Backward-compat: a legacy `agent.state` doesn't have
        // `coord_iroh_relay_url` / `coord_iroh_direct_addrs`.
        // It MUST still load (None + empty vec defaults), so an in-place
        // upgrade doesn't refuse to start. The dial site treats the empty
        // case as "no addrs known" — which under hermetic mode then surfaces
        // as a re-register-and-refresh loop, per coord_conn's auth-fail handler.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        // Write only the legacy fields by hand.
        let legacy_json = serde_json::json!({
            "alias": "legacy-alias",
            "coord_domain": "coord.p2claw.com",
            "parent_domain": "p2claw.com",
            "coord_root_pubkey_b64url": B64_URL.encode([0xAB; 32]),
        });
        fs::write(&p, serde_json::to_vec_pretty(&legacy_json).unwrap()).unwrap();

        let got = load(&p).unwrap().expect("legacy state must load");
        assert_eq!(got.alias, "legacy-alias");
        assert!(
            got.coord_iroh_relay_url.is_none(),
            "missing field defaults to None"
        );
        assert!(
            got.coord_iroh_direct_addrs.is_empty(),
            "missing field defaults to empty Vec"
        );
    }

    /// `coord_root_pubkey` round-trips through the on-disk
    /// base64url encoding. Asserts the codec wired in via
    /// `serialize_with` / `deserialize_with` agrees with itself
    /// across save/load.
    #[test]
    fn coord_root_pubkey_b64url_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.state");
        let s = sample();
        save(&p, &s).unwrap();
        let raw = fs::read_to_string(&p).unwrap();
        // The PEM-style 0xAB-byte pubkey base64url-encodes to a
        // long string of `q`s — easy to spot in the JSON.
        assert!(
            raw.contains("\"coord_root_pubkey_b64url\""),
            "agent.state must include the new field:\n{raw}"
        );
        let got = load(&p).unwrap().expect("state present");
        assert_eq!(got.coord_root_pubkey.as_bytes(), &[0xAB; 32]);
    }
}
