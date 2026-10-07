//! Atomic, owner-only file writes for state the agent keeps on disk.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` atomically: temp file next to it, mode
/// 0600, fsync, rename. The parent directory is created (0700) if
/// missing.
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
