//! Inbound email for the box: settings the owner controls, the inbox
//! that holds delivered mail, and the client side of coord's mail
//! queue.
//!
//! Coord only ever holds ciphertext; the box opens each sealed message
//! with the X25519 key derived from its identity key and keeps the
//! plaintext under its state directory, protected by file permissions
//! like everything else there. Mail stays until an app or the owner
//! deletes it; acking only marks it handled.
//!
//! Modules: [`settings`] (enabled flag, allowlist, approved
//! forwarders, addresses coord assigned), [`inbox`] (message store and
//! forwarding requests), [`render`] (message records out of the raw
//! RFC 5322 bytes), [`forwarding`] (Gmail confirmation parsing),
//! [`stream`] (the `email` stream protocol) and [`drain`] (pulling the
//! queue into the inbox).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod drain;
pub mod forwarding;
pub mod inbox;
pub mod render;
pub mod settings;
pub mod stream;

pub use drain::{drain, DrainReport};
pub use inbox::{Entry, EntryKind, ForwardingRequest, Inbox, InboxError};
pub use settings::{EmailConfig, EmailSettings, SettingsError};
pub use stream::{EmailStream, StreamError};

/// Why an address can't go on the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("`{0}` is not an email address")]
    Malformed(String),
}

/// Canonical form of an address for allowlist and forwarder entries:
/// trimmed, lower-cased, plus-tag removed from the local part so
/// `You+x@Gmail.com` and `you@gmail.com` are the same entry. Exact
/// addresses only; no domain-wide entries.
pub fn normalize_address(raw: &str) -> Result<String, AddressError> {
    let s = raw.trim().to_ascii_lowercase();
    let Some((local, domain)) = s.rsplit_once('@') else {
        return Err(AddressError::Malformed(raw.trim().to_string()));
    };
    let local = local.split_once('+').map(|(l, _)| l).unwrap_or(local);
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || s.chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>' || c == ',')
    {
        return Err(AddressError::Malformed(raw.trim().to_string()));
    }
    Ok(format!("{local}@{domain}"))
}

/// Unix seconds as an RFC 3339 UTC timestamp (`2026-10-04T15:02:11Z`).
pub fn rfc3339(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// Days since 1970-01-01 to a proleptic Gregorian date (Howard
// Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `bytes` to `path` atomically: temp file next to it, mode
/// 0600, fsync, rename.
pub(crate) fn write_atomic_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = temp_path(path);
    write_file_0600(&tmp, bytes)?;
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

    #[test]
    fn normalize_lowercases_and_strips_plus_tags() {
        assert_eq!(
            normalize_address(" You+x@Gmail.COM "),
            Ok("you@gmail.com".into())
        );
        assert_eq!(normalize_address("a+b+c@x.org"), Ok("a@x.org".into()));
        assert_eq!(normalize_address("plain@x.org"), Ok("plain@x.org".into()));
    }

    #[test]
    fn normalize_rejects_non_addresses() {
        for bad in [
            "",
            "@x.org",
            "a@",
            "a@localhost",
            "a b@x.org",
            "<a@x.org>",
            "a@.x",
            "a,b@x.org",
        ] {
            assert!(normalize_address(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_126_131), "2026-10-04T15:02:11Z");
    }
}
