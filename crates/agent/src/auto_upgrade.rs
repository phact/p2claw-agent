//! Auto-upgrade infrastructure — agent-side.
//!
//! Hourly automatic upgrade of the running binary against GitHub
//! Releases, with SHA-256 verification, atomic swap, rollback and
//! a post-upgrade health check.
//!
//! ## Fetch path
//!
//! Everything stays on GitHub. Four URLs, all CDN-served, no API
//! rate limit, no signing key, no edge route, no coord endpoint:
//!
//! 1. `GET https://github.com/<repo>/releases/latest`
//!    → 302 → `Location: https://github.com/<repo>/releases/tag/v<version>`.
//!    Parse the version from the Location header (last path
//!    segment, strip leading `v`).
//! 2. `GET https://github.com/<repo>/releases/download/v<version>/SHA256SUMS`
//!    → text body of `<hex-sha256>  <filename>` lines (one per
//!    asset). Parse into a `HashMap<String, [u8; 32]>`.
//! 3. Pick our platform's tarball filename
//!    (`p2claw-v<version>-<os>-<arch>.tar.gz`); look up its
//!    expected SHA-256 in the SHA256SUMS map.
//! 4. `GET https://github.com/<repo>/releases/download/v<version>/<filename>`
//!    streams the gzipped tarball; we hash as-it-arrives, verify
//!    against (3), then extract the inner binary.
//!
//! ## Repo override (OSS forks)
//!
//! `P2CLAW_RELEASE_REPO=<org>/<repo>` env var → agent points at
//! `https://github.com/<org>/<repo>/releases/latest`. Forkers
//! don't need our repo or any custom infra. Default is
//! `phact/p2claw-skill`.
//!
//! ## Update-check policy
//!
//! Hourly poll. CDN URLs have no rate limit so the per-NAT
//! cardinality isn't a concern. No exponential backoff on
//! failure — just retry next cycle. Eventual consistency is
//! fine here; we're not racing against a deadline.
//!
//! ## Integrity
//!
//! SHA-256 from SHA256SUMS is the only integrity check; the trust
//! root is GitHub-the-host (the CDN serves SHA256SUMS and the
//! tarball over the same TLS chain). It protects against transit
//! corruption and a compromised CDN edge.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

/// Default GH `<org>/<repo>` to fetch releases from. Operators
/// running a fork point at their own via the
/// `P2CLAW_RELEASE_REPO` env var.
pub const DEFAULT_RELEASE_REPO: &str = "phact/p2claw-skill";

/// Env-var name for the OSS-fork override.
pub const RELEASE_REPO_ENV: &str = "P2CLAW_RELEASE_REPO";

/// Build the latest-release redirect URL for `<org>/<repo>`.
/// HTTP GET against this URL returns a 302 with
/// `Location: …/releases/tag/v<version>`.
pub fn latest_release_url(repo: &str) -> String {
    format!("https://github.com/{repo}/releases/latest")
}

/// Build the download URL for an asset in the release tagged
/// `v<version>`. Used for both `SHA256SUMS` and the per-platform
/// tarball.
pub fn release_asset_url(repo: &str, version: &str, asset: &str) -> String {
    format!("https://github.com/{repo}/releases/download/v{version}/{asset}")
}

/// Resolve the release repo from the env (or fall back to the
/// default). Operators can swap repos without rebuilding.
pub fn resolve_release_repo() -> String {
    match std::env::var(RELEASE_REPO_ENV) {
        Ok(v) => {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
            DEFAULT_RELEASE_REPO.to_string()
        }
        Err(_) => DEFAULT_RELEASE_REPO.to_string(),
    }
}

/// Cadence for the latest-release poll. Hourly is cheap (one
/// HEAD-shaped redirect + one SHA256SUMS GET per cycle when no
/// upgrade is needed) and gets a fix to users within ~1h of a
/// release going live.
pub const POLL_INTERVAL: Duration = Duration::from_secs(3_600);

/// Per-fetch timeout. GH's CDN responds fast; 10s comfortably
/// covers a slow-link client without hanging the upgrade task.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Compute the per-platform tarball asset filename for `version`.
/// Mirrors the GH Actions `release.yml` build matrix:
/// `p2claw-v<version>-<os>-<arch>.tar.gz`.
///
/// Returns `None` on platforms outside the build matrix
/// (Windows, FreeBSD, etc.) so the orchestrator can fail with
/// `Unsupported` rather than 404 against a non-existent asset.
pub fn current_platform_asset(version: &str) -> Option<String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        _ => return None,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return None,
    };
    Some(format!("p2claw-v{version}-{os}-{arch}.tar.gz"))
}

#[derive(Debug, Error)]
pub enum AutoUpgradeError {
    #[error("http fetch: {0}")]
    Http(#[source] reqwest::Error),
    #[error("latest-release redirect missing Location header")]
    NoRedirectLocation,
    #[error("latest-release redirect Location did not parse as a release tag URL: {0}")]
    BadRedirectLocation(String),
    #[error("version `{0}`: {1}")]
    BadVersion(String, semver::Error),
    #[error("SHA256SUMS body parse failed: {0}")]
    Sha256SumsParse(String),
    #[error("SHA256SUMS has no entry for asset `{0}`")]
    Sha256SumsNoEntry(String),
    #[error("running platform (os={os}, arch={arch}) is not in the release matrix")]
    UnsupportedPlatform {
        os: &'static str,
        arch: &'static str,
    },
}

/// Resolved latest-release pointer plus the bits the orchestrator
/// needs to download + verify the platform tarball.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRelease {
    /// Semver from the redirect Location's `tag/v<version>` segment.
    pub version: String,
    /// Asset filename for this platform (built via
    /// [`current_platform_asset`]).
    pub asset: String,
    /// Full download URL for the asset.
    pub asset_url: String,
    /// Expected SHA-256 of the asset bytes (raw 32 bytes), looked
    /// up in the SHA256SUMS file.
    pub asset_sha256: [u8; 32],
}

/// Outcome of [`should_upgrade`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeDecision {
    /// `latest.version` is strictly newer than `self_version` —
    /// proceed to download.
    Upgrade,
    /// `latest.version` <= `self_version`. Common steady-state.
    AlreadyAtOrAhead,
}

/// Decide whether to upgrade. Pure on `(self_version, latest)`.
pub fn should_upgrade(
    self_version: &str,
    latest: &LatestRelease,
) -> Result<UpgradeDecision, AutoUpgradeError> {
    let self_v = Version::parse(self_version)
        .map_err(|e| AutoUpgradeError::BadVersion(self_version.to_string(), e))?;
    let latest_v = Version::parse(&latest.version)
        .map_err(|e| AutoUpgradeError::BadVersion(latest.version.clone(), e))?;
    if latest_v <= self_v {
        return Ok(UpgradeDecision::AlreadyAtOrAhead);
    }
    Ok(UpgradeDecision::Upgrade)
}

/// HTTP-fetch the latest-release redirect, parse the version from
/// the Location header, then GET the SHA256SUMS file for that
/// version and look up our platform asset's hash. Returns a
/// fully-resolved [`LatestRelease`] the orchestrator can drive.
///
/// Bounded by [`FETCH_TIMEOUT`] per request (two requests total).
pub async fn fetch_latest_release(repo: &str) -> Result<LatestRelease, AutoUpgradeError> {
    let latest_url = latest_release_url(repo);
    debug!(%latest_url, "auto_upgrade: fetching latest-release redirect");

    // Step 1: Fetch the latest-release URL with redirects DISABLED
    // so we can read the Location header. reqwest's default policy
    // follows up to 10 redirects; we override to no-follow.
    let client_no_redirect = reqwest::Client::builder()
        .user_agent(concat!("p2claw-agent/", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(AutoUpgradeError::Http)?;
    let resp = client_no_redirect
        .get(&latest_url)
        .send()
        .await
        .map_err(AutoUpgradeError::Http)?;
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AutoUpgradeError::NoRedirectLocation)?;
    let version = parse_version_from_release_tag_url(location)?;
    debug!(%version, "auto_upgrade: parsed version from redirect Location");

    // Step 2: Fetch SHA256SUMS for that version. Standard client
    // (follows redirects — GH may serve assets from objects.gh CDN
    // via a 302 hop).
    let client = reqwest::Client::builder()
        .user_agent(concat!("p2claw-agent/", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(AutoUpgradeError::Http)?;
    let sha256sums_url = release_asset_url(repo, &version, "SHA256SUMS");
    let sha256sums_body = client
        .get(&sha256sums_url)
        .send()
        .await
        .map_err(AutoUpgradeError::Http)?
        .error_for_status()
        .map_err(AutoUpgradeError::Http)?
        .text()
        .await
        .map_err(AutoUpgradeError::Http)?;
    let sums = parse_sha256sums(&sha256sums_body)?;

    // Step 3: Resolve our platform asset filename + look it up.
    let asset = current_platform_asset(&version).ok_or(AutoUpgradeError::UnsupportedPlatform {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    })?;
    let asset_sha256 = *sums
        .get(&asset)
        .ok_or_else(|| AutoUpgradeError::Sha256SumsNoEntry(asset.clone()))?;
    let asset_url = release_asset_url(repo, &version, &asset);

    Ok(LatestRelease {
        version,
        asset,
        asset_url,
        asset_sha256,
    })
}

/// Parse the version from a `…/releases/tag/v<version>` URL.
/// GH always emits `v<semver>` in the tag URL; we strip the
/// leading `v` so the rest of the orchestrator can semver-parse it.
fn parse_version_from_release_tag_url(url: &str) -> Result<String, AutoUpgradeError> {
    let last = url
        .rsplit('/')
        .find(|s| !s.is_empty())
        .ok_or_else(|| AutoUpgradeError::BadRedirectLocation(url.to_string()))?;
    let stripped = last
        .strip_prefix('v')
        .ok_or_else(|| AutoUpgradeError::BadRedirectLocation(url.to_string()))?;
    if stripped.is_empty() {
        return Err(AutoUpgradeError::BadRedirectLocation(url.to_string()));
    }
    Ok(stripped.to_string())
}

/// Parse a SHA256SUMS file body into `filename → 32-byte digest`.
/// Each line is `<64-hex-chars>  <filename>\n` per coreutils
/// `sha256sum` output (two-space separator). Lines starting with
/// `#` and blank lines are ignored.
///
/// We accept the GNU-style two-space separator; some toolchains
/// use a single space — also accepted defensively.
fn parse_sha256sums(
    body: &str,
) -> Result<std::collections::HashMap<String, [u8; 32]>, AutoUpgradeError> {
    let mut out = std::collections::HashMap::new();
    for (lineno, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Hex digest (64 chars), then whitespace, then filename.
        // Mode prefix (' ' or '*') in front of the filename per
        // the BSD-style format is allowed; we just skip it.
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = parts.next().ok_or_else(|| {
            AutoUpgradeError::Sha256SumsParse(format!("line {}: empty", lineno + 1))
        })?;
        let rest = parts.next().ok_or_else(|| {
            AutoUpgradeError::Sha256SumsParse(format!("line {}: missing filename", lineno + 1))
        })?;
        if hex.len() != 64 {
            return Err(AutoUpgradeError::Sha256SumsParse(format!(
                "line {}: digest length {}, expected 64 hex chars",
                lineno + 1,
                hex.len()
            )));
        }
        let mut digest = [0u8; 32];
        for i in 0..32 {
            digest[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
                AutoUpgradeError::Sha256SumsParse(format!(
                    "line {}: digest byte {} not hex",
                    lineno + 1,
                    i
                ))
            })?;
        }
        let filename = rest.trim_start_matches([' ', '*']).trim().to_string();
        out.insert(filename, digest);
    }
    if out.is_empty() {
        return Err(AutoUpgradeError::Sha256SumsParse(
            "no entries parsed".to_string(),
        ));
    }
    Ok(out)
}

// ===== Download + verify + extract + atomic swap ======================

/// Hard cap on a downloaded asset. Way over the realistic
/// agent tarball size (~15 MiB compressed at the time of
/// writing) but small enough that a misbehaving / malicious
/// release can't fill the disk with a download.
/// (bound everything that takes attacker-influenced
/// input).
pub const MAX_BINARY_BYTES: u64 = 200 * 1024 * 1024;

/// Per-fetch download timeout. Slow streams shouldn't pin the
/// upgrade task forever; if the CDN stalls we'd rather fail
/// and retry next cycle.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Suffix appended to the canonical binary path to keep the
/// previous version for one upgrade cycle. The watchdog's
/// rollback restores from this if the new binary fails to start.
pub const PREVIOUS_BINARY_SUFFIX: &str = ".previous";

#[derive(Debug, Error)]
pub enum BinaryError {
    #[error("download http: {0}")]
    Http(#[source] reqwest::Error),
    #[error("download too large: {actual} bytes exceeds cap {cap}")]
    TooLarge { actual: u64, cap: u64 },
    #[error("download stream timed out after {0:?}")]
    Timeout(Duration),
    #[error("downloaded SHA-256 mismatch: expected {expected} got {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("tarball extraction: {0}")]
    TarExtract(String),
    #[error("tarball did not contain a `p2claw` binary")]
    NoBinaryInTarball,
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Verify a downloaded asset's bytes match the expected SHA-256
/// from the SHA256SUMS file. The only integrity check; trust root
/// is GitHub-the-host (the CDN that served SHA256SUMS + the tarball
/// over the same TLS chain).
///
/// Pure on `(asset_bytes, expected_digest)`; testable in
/// isolation.
pub fn verify_sha256(asset_bytes: &[u8], expected: &[u8; 32]) -> Result<(), BinaryError> {
    let mut hasher = Sha256::new();
    hasher.update(asset_bytes);
    let actual = hasher.finalize();
    if actual.as_slice() != expected.as_slice() {
        return Err(BinaryError::Sha256Mismatch {
            expected: hex_encode(expected),
            actual: hex_encode(actual.as_slice()),
        });
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Extract the `p2claw` binary from a downloaded tarball at
/// `tarball_path` to `dest_binary`. Tarball layout per the GH
/// Actions release.yml: a single top-level `p2claw` (or
/// `p2claw.exe` on Windows — not currently in the matrix) entry.
/// Other entries (README, LICENSE) are skipped.
///
/// Sets the destination file's mode to 0755 on Unix so the
/// supervised restart can exec it. The `tar` crate's
/// `unpack_in` doesn't honor the entry's mode field reliably
/// across platforms; we set it explicitly post-write.
pub fn extract_binary_from_tarball(
    tarball_path: &Path,
    dest_binary: &Path,
) -> Result<(), BinaryError> {
    use std::io::Read as _;
    let f = std::fs::File::open(tarball_path).map_err(|e| BinaryError::Io {
        path: tarball_path.display().to_string(),
        source: e,
    })?;
    let gz = flate2::read::GzDecoder::new(f);
    let mut archive = tar::Archive::new(gz);
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|e| BinaryError::TarExtract(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| BinaryError::TarExtract(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| BinaryError::TarExtract(e.to_string()))?;
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if filename != "p2claw" {
            continue;
        }
        // Stream the entry to dest_binary.
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest_binary)
            .map_err(|e| BinaryError::Io {
                path: dest_binary.display().to_string(),
                source: e,
            })?;
        let mut buf = Vec::with_capacity(64 * 1024);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| BinaryError::TarExtract(e.to_string()))?;
        use std::io::Write as _;
        out.write_all(&buf).map_err(|e| BinaryError::Io {
            path: dest_binary.display().to_string(),
            source: e,
        })?;
        out.sync_all().map_err(|e| BinaryError::Io {
            path: dest_binary.display().to_string(),
            source: e,
        })?;
        drop(out);
        // Make executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dest_binary)
                .map_err(|e| BinaryError::Io {
                    path: dest_binary.display().to_string(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dest_binary, perms).map_err(|e| BinaryError::Io {
                path: dest_binary.display().to_string(),
                source: e,
            })?;
        }
        found = true;
        break;
    }
    if !found {
        return Err(BinaryError::NoBinaryInTarball);
    }
    Ok(())
}

/// Stream-download an asset (tarball) from `url` to `dest`.
/// Hashes as-it-arrives so we can fail fast on size mismatch
/// without buffering the full content in memory. Bounded by
/// [`MAX_BINARY_BYTES`] + [`DOWNLOAD_TIMEOUT`].
///
/// Returns the SHA-256 of the downloaded bytes. Caller passes
/// this to [`verify_sha256`] (against the SHA256SUMS-derived
/// expected digest) before invoking [`extract_binary_from_tarball`]
/// + [`atomic_swap`].
///
/// Despite the name (kept for callsite continuity), the bytes
/// downloaded here are the gzipped tarball,
/// not the bare binary. Extraction is a separate step.
pub async fn download_binary(url: &str, dest: &Path) -> Result<[u8; 32], BinaryError> {
    debug!(%url, dest = %dest.display(), "auto_upgrade: downloading binary");
    let client = reqwest::Client::builder()
        .user_agent(concat!("p2claw-agent/", env!("CARGO_PKG_VERSION")))
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(BinaryError::Http)?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(BinaryError::Http)?
        .error_for_status()
        .map_err(BinaryError::Http)?;

    // Open dest for writing — caller's responsibility to
    // pre-validate the path (parent exists, sane filename).
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| BinaryError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BinaryError::Http)?;
        total += chunk.len() as u64;
        if total > MAX_BINARY_BYTES {
            return Err(BinaryError::TooLarge {
                actual: total,
                cap: MAX_BINARY_BYTES,
            });
        }
        hasher.update(&chunk);
        use tokio::io::AsyncWriteExt;
        file.write_all(&chunk).await.map_err(|e| BinaryError::Io {
            path: dest.display().to_string(),
            source: e,
        })?;
    }
    use tokio::io::AsyncWriteExt;
    file.flush().await.map_err(|e| BinaryError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    file.sync_all().await.map_err(|e| BinaryError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;
    drop(file);

    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_slice());
    Ok(out)
}

/// Atomically swap `new_temp` into `canonical`, preserving the
/// previous canonical at `canonical.previous` for one rollback
/// cycle. Order:
///
///   1. If `canonical` exists, rename it to `canonical.previous`
///      (overwriting any older `.previous` from a prior cycle).
///   2. Rename `new_temp` to `canonical`.
///   3. fsync the parent directory so the rename(s) hit disk.
///
/// All-or-nothing in the failure-mode sense: a crash between (1)
/// and (2) leaves `.previous` in place + `canonical` missing,
/// which the upgrade orchestrator recovers from by rolling back
/// to `.previous`.
pub fn atomic_swap(canonical: &Path, new_temp: &Path) -> Result<(), BinaryError> {
    let previous = previous_path(canonical);
    if canonical.exists() {
        std::fs::rename(canonical, &previous).map_err(|e| BinaryError::Io {
            path: previous.display().to_string(),
            source: e,
        })?;
    }
    std::fs::rename(new_temp, canonical).map_err(|e| BinaryError::Io {
        path: canonical.display().to_string(),
        source: e,
    })?;
    if let Some(parent) = canonical.parent() {
        // Best-effort dir fsync — if it fails, the rename(s)
        // still happened; we just lose the durability guarantee
        // on the metadata. Logged at warn so operators can see
        // it during diagnosis.
        if let Err(e) = fsync_dir(parent) {
            warn!(dir = %parent.display(), error = %e, "auto_upgrade: dir fsync failed; rename committed but not durable");
        }
    }
    Ok(())
}

/// Rollback: swap `canonical.previous` back into `canonical`,
/// discarding the failed new binary. Used by the orchestrator's
/// three-strike guard when the just-installed binary fails to
/// start cleanly.
pub fn restore_previous(canonical: &Path) -> Result<(), BinaryError> {
    let previous = previous_path(canonical);
    if !previous.exists() {
        return Err(BinaryError::Io {
            path: previous.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no `.previous` to roll back to",
            ),
        });
    }
    std::fs::rename(&previous, canonical).map_err(|e| BinaryError::Io {
        path: canonical.display().to_string(),
        source: e,
    })?;
    if let Some(parent) = canonical.parent() {
        if let Err(e) = fsync_dir(parent) {
            warn!(dir = %parent.display(), error = %e, "auto_upgrade: rollback dir fsync failed");
        }
    }
    Ok(())
}

/// Drop the `.previous` file once the orchestrator's "new binary
/// survived N seconds clean" check has fired. Call only after a
/// successful upgrade; a premature call burns the rollback option.
pub fn keep_previous(canonical: &Path) -> PathBuf {
    previous_path(canonical)
}

fn previous_path(canonical: &Path) -> PathBuf {
    let mut s = canonical.as_os_str().to_os_string();
    s.push(PREVIOUS_BINARY_SUFFIX);
    PathBuf::from(s)
}

/// fsync a directory so its rename metadata hits disk. Cross-
/// platform (Linux supports O_DIRECTORY + fsync; macOS +
/// Windows treat it as a no-op gracefully through the std::fs
/// abstraction).
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let f = std::fs::File::open(dir)?;
    f.sync_all()
}

// ===== Orchestrator + post-upgrade health watchdog ============
//
// The helpers above are pure; the orchestrator below is the glue
// that drives them on a schedule (hourly in-process supervised
// task) and on demand (`p2claw upgrade --apply`), and the
// watchdog the new process runs at startup to roll back if the
// freshly-installed binary fails to come up.
//
// Watchdog design: invert "old watches new" — that doesn't work
// because the OS supervisor (systemctl restart / launchctl
// kickstart) kills the old process before the new one starts. So
// the new process self-watches via
// (a) local-API bind success — the load-bearing signal, and
// (b) best-effort coord hello_ack — bonus signal that gracefully
// degrades to `HealthyCoordUnreachable` when the user's network
// is having trouble.

/// Coarse-grained liveness signal published by the coord-
/// connection loop and consumed by the post-upgrade watchdog
/// (`watchdog::post_upgrade_health_check`). Defined here in the
/// lib so the watchdog can `use super::CoordHealth` without
/// crossing target boundaries (`coord_conn` lives in the bin
/// target and re-exports this type via
/// `pub use p2claw_agent::auto_upgrade::CoordHealth`).
///
/// Per the design call: the bonus signal that "we
/// successfully completed a hello_ack against coord within the
/// health-check budget" upgrades a watchdog result from
/// `HealthyCoordUnreachable` to `Healthy`. Absence is graceful —
/// the user's network being weird shouldn't trigger a rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordHealth {
    /// Initial state and between dial attempts. The loop is
    /// actively trying to reach coord but hasn't completed a
    /// hello_ack yet.
    Connecting,
    /// Most recent QUIC session got past the hello_ack handshake.
    /// "All systems go" — the bonus signal the watchdog watches
    /// for during its budget.
    ConnectedHelloAck,
    /// A connected session ended (closed, errored, revoked,
    /// superseded). Will transition back to `Connecting` on the
    /// next loop iteration.
    Disconnected,
}

/// On-disk filename of the upgrade-in-progress flag. Lives in the
/// agent's data dir alongside `agent.state` and `identity.key`.
pub const UPGRADE_IN_PROGRESS_FILENAME: &str = "upgrade-in-progress.json";

/// Health-check budget the new process gets to prove itself.
/// Local-API bind happens within milliseconds in normal startup;
/// the budget mostly accommodates coord network latency for the
/// bonus hello_ack signal. Beyond this window we declare
/// `Unhealthy` and roll back to `<canonical>.previous`.
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Persisted upgrade-in-progress flag. Written atomically (write
/// to `<filename>.tmp` + rename) before the orchestrator triggers
/// the supervised restart; consumed by the new process's watchdog
/// at startup. Schema is JSON for human-readability — if the
/// rollback path goes weird, an operator can `cat` the flag and
/// see what's in flight.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeInProgress {
    /// SemVer the orchestrator expected to bring up.
    pub target_version: String,
    /// SemVer the orchestrator was running BEFORE the swap.
    /// Surfaced in logs + lets future tooling sanity-check the
    /// `.previous` file's actual version.
    pub from_version: String,
    /// Unix epoch seconds when the orchestrator triggered the
    /// restart. Surfaced in logs.
    pub started_at_unix: i64,
}

/// Read the upgrade-in-progress flag from `data_dir`. Returns
/// `Ok(None)` when the file doesn't exist (the steady-state cold-
/// start case) — this is NOT an error. `Ok(Some(_))` means the new
/// process should run the watchdog. A malformed file is logged at
/// `warn!` and treated as absent (best-effort on a flag that's
/// only advisory).
pub fn read_upgrade_in_progress(data_dir: &Path) -> std::io::Result<Option<UpgradeInProgress>> {
    let path = data_dir.join(UPGRADE_IN_PROGRESS_FILENAME);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<UpgradeInProgress>(&bytes) {
            Ok(flag) => Ok(Some(flag)),
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "auto_upgrade: upgrade-in-progress flag is malformed; treating as absent"
                );
                Ok(None)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically write the upgrade-in-progress flag to `data_dir`.
/// Called by the orchestrator just before the restart trigger.
pub fn write_upgrade_in_progress(data_dir: &Path, flag: &UpgradeInProgress) -> std::io::Result<()> {
    let path = data_dir.join(UPGRADE_IN_PROGRESS_FILENAME);
    let bytes = serde_json::to_vec(flag)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    std::fs::write(&tmp_path, &bytes)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Remove the upgrade-in-progress flag. Called by the watchdog
/// after a `Healthy` outcome (the upgrade has stuck) and by the
/// rollback path before the rolled-back process restarts (so it
/// doesn't re-run the watchdog on its next start). Idempotent —
/// missing-file returns Ok.
pub fn clear_upgrade_in_progress(data_dir: &Path) -> std::io::Result<()> {
    let path = data_dir.join(UPGRADE_IN_PROGRESS_FILENAME);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub mod policy {
    //! Operator-facing policy
    //! controls on top of the auto-upgrade infrastructure: pin to
    //! a specific version (refuse upgrades past it) and disable
    //! (turn off the orchestrator entirely). Both persist as
    //! small files in the agent's data dir; the orchestrator
    //! reads them on every cycle, the CLI surfaces them via
    //! `p2claw upgrade --pin / --unpin / --disable / --enable /
    //! --status`.

    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Serialize};
    use tracing::warn;

    /// JSON file holding the pinned version. Presence means
    /// "refuse upgrades past `version`"; absence means "no pin in
    /// effect, normal upgrade flow."
    pub const PIN_FILENAME: &str = "upgrade-pin.json";

    /// Sentinel file. Presence means "the operator has disabled
    /// auto-upgrade; the orchestrator must not run." Absence
    /// means "normal upgrade flow." Empty file — only the
    /// presence/absence matters.
    pub const DISABLED_FILENAME: &str = "upgrade-disabled";

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct UpgradePin {
        /// SemVer string. Stored as a string (not a parsed
        /// `Version`) so the on-disk shape is forward-compatible
        /// with future SemVer pre-release / build-metadata
        /// extensions without a migration.
        pub version: String,
    }

    /// Read the pin file. Returns `Ok(None)` when absent — NOT an
    /// error. Malformed → log + treat as absent (best-effort on a
    /// policy file the operator may have hand-edited).
    pub fn read_pin(data_dir: &Path) -> std::io::Result<Option<UpgradePin>> {
        let path = pin_path(data_dir);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<UpgradePin>(&bytes) {
                Ok(p) => Ok(Some(p)),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "auto_upgrade::policy: pin file is malformed; treating as absent"
                    );
                    Ok(None)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Atomically write the pin file. `.tmp + rename` so a torn
    /// write can't leave a half-written JSON file in place.
    pub fn write_pin(data_dir: &Path, pin: &UpgradePin) -> std::io::Result<()> {
        let path = pin_path(data_dir);
        let bytes = serde_json::to_vec(pin)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp_path = PathBuf::from(tmp);
        std::fs::write(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Remove the pin file. Idempotent — missing returns Ok.
    pub fn clear_pin(data_dir: &Path) -> std::io::Result<()> {
        let path = pin_path(data_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Is auto-upgrade disabled? Cheap presence-check on the
    /// sentinel file — no parsing.
    pub fn is_disabled(data_dir: &Path) -> bool {
        disabled_path(data_dir).exists()
    }

    /// Mark auto-upgrade as disabled. Writes an empty sentinel
    /// file so `is_disabled` returns true. Idempotent.
    pub fn set_disabled(data_dir: &Path) -> std::io::Result<()> {
        let path = disabled_path(data_dir);
        // create_new would fail-on-exists; we want idempotent
        // "ensure exists" semantics, so plain `write` of empty.
        std::fs::write(path, b"")
    }

    /// Re-enable auto-upgrade. Removes the sentinel. Idempotent.
    pub fn clear_disabled(data_dir: &Path) -> std::io::Result<()> {
        let path = disabled_path(data_dir);
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn pin_path(data_dir: &Path) -> PathBuf {
        data_dir.join(PIN_FILENAME)
    }

    fn disabled_path(data_dir: &Path) -> PathBuf {
        data_dir.join(DISABLED_FILENAME)
    }
}

pub mod orchestrator {
    //! The function the agent calls hourly + the CLI's
    //! `--check` / `--apply` invoke.
    //!
    //! One async function:
    //! look up latest release → decide → (if Upgrade) download → verify →
    //! atomic_swap → drift-rewrite service-config → write flag →
    //! trigger supervised restart. The restart trigger is
    //! injectable so tests don't actually `systemctl restart` the
    //! host's running service.

    use std::sync::Arc;

    use super::{
        atomic_swap, download_binary, extract_binary_from_tarball, fetch_latest_release,
        should_upgrade, verify_sha256, write_upgrade_in_progress, AutoUpgradeError, BinaryError,
        UpgradeDecision, UpgradeInProgress,
    };
    use std::path::PathBuf;
    use thiserror::Error;
    use tracing::{debug, info, warn};

    /// Pluggable platform-specific restart trigger. Returns once
    /// the OS supervisor has been asked to restart; the actual
    /// process death happens on the supervisor's schedule
    /// (typically within a second). Wrapped in `Arc` so the
    /// orchestrator + the CLI's `--apply` path can share the same
    /// default impl without ownership gymnastics.
    pub type RestartTrigger = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

    #[derive(Debug, Error)]
    pub enum OrchestratorError {
        #[error("release lookup + decision: {0}")]
        Manifest(#[from] AutoUpgradeError),
        #[error("download / verify / swap: {0}")]
        Binary(#[from] BinaryError),
        #[error("could not write upgrade-in-progress flag in {data_dir}: {source}")]
        FlagWrite {
            data_dir: String,
            #[source]
            source: std::io::Error,
        },
        #[error("could not trigger supervised restart: {0}")]
        RestartTrigger(#[source] std::io::Error),
        #[error("could not read swapped binary back for verify at {path}: {source}")]
        ReadBack {
            path: String,
            #[source]
            source: std::io::Error,
        },
    }

    /// Per-call options for [`run_once`]. Built fresh each cycle —
    /// the orchestrator owns no state of its own (the running
    /// version comes from `env!("CARGO_PKG_VERSION")` at the call
    /// site; the canonical-binary path comes from
    /// `std::env::current_exe`).
    pub struct OrchestratorOpts {
        /// GitHub `<org>/<repo>` to fetch releases from. Default
        /// production callers pass `super::resolve_release_repo()`
        /// which honors the `P2CLAW_RELEASE_REPO` env override
        /// for OSS forks. Tests pass an `httpmock`-backed shim
        /// (or skip the orchestrator entirely and exercise the
        /// inner pure functions).
        pub release_repo: String,
        pub self_version: String,
        /// Filesystem path of the running binary. Orchestrator
        /// downloads the tarball to `<canonical>.tar.gz.new`,
        /// extracts the inner binary to `<canonical>.new`,
        /// verifies, then atomically swaps + preserves the
        /// previous version at `<canonical>.previous` for one
        /// rollback cycle.
        pub canonical_binary: PathBuf,
        /// Data dir — used to persist the upgrade-in-progress flag.
        pub data_dir: PathBuf,
        /// Trigger function invoked after `atomic_swap` +
        /// flag-write to restart the new binary under its
        /// supervisor. Default impl
        /// ([`default_restart_trigger`]) calls
        /// `systemctl --user restart` / `launchctl kickstart`.
        /// Tests inject a no-op.
        pub restart_trigger: RestartTrigger,
    }

    /// Result of a single orchestrator invocation. `Upgraded` is
    /// the "we triggered a restart" path — under normal supervised
    /// operation the caller may not see it because the process
    /// dies under the restart. The CLI `--apply` path may see it
    /// because it's a separate process from the restarted daemon.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OrchestratorOutcome {
        Upgraded {
            from: String,
            to: String,
        },
        /// Binary swapped + upgrade-in-progress flag written, but the
        /// supervised restart trigger failed — typically because the
        /// box has no systemd/launchd unit (a manually-run
        /// `p2claw run`). The new binary is staged on disk; the
        /// operator must restart the daemon to apply. Distinct from
        /// `Upgraded` so the CLI reports a clear "restart required"
        /// instead of a misleading hard error. The in-progress flag
        /// is intentionally left in place so the eventual restart's
        /// watchdog runs its health-check / rollback as normal.
        StagedPendingManualRestart {
            from: String,
            to: String,
        },
        SkippedAlreadyAtOrAhead,
        /// Operator pinned the agent to a specific version;
        /// latest release is past the pin. No download, no swap.
        /// Cleared by `p2claw upgrade --unpin`.
        SkippedPinned {
            pinned: String,
            latest: String,
        },
        /// Operator disabled auto-upgrade entirely. No
        /// release fetch, no decision. Cleared by
        /// `p2claw upgrade --enable`.
        SkippedDisabled,
    }

    /// Run one orchestrator cycle. Idempotent on the
    /// non-`Upgrade` branches; on `Upgrade`, the restart trigger
    /// fires exactly once per cycle.
    pub async fn run_once(
        opts: &OrchestratorOpts,
    ) -> Result<OrchestratorOutcome, OrchestratorError> {
        // Policy short-circuits — checked BEFORE the release
        // lookup so a disabled agent doesn't bother the CDN, and
        // `p2claw upgrade --status` reflects current state without
        // touching the network.
        if super::policy::is_disabled(&opts.data_dir) {
            debug!(
                data_dir = %opts.data_dir.display(),
                "auto_upgrade::orchestrator: disabled by policy file; skipping cycle"
            );
            return Ok(OrchestratorOutcome::SkippedDisabled);
        }
        let pin = match super::policy::read_pin(&opts.data_dir) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "auto_upgrade::orchestrator: pin file read failed; treating as unpinned");
                None
            }
        };

        let latest = fetch_latest_release(&opts.release_repo).await?;
        // Pin check happens AFTER latest-release fetch so we have
        // the version to compare against. Pin is a SemVer ceiling:
        // refuse upgrades to a release strictly greater than the pin.
        if let Some(pin) = pin.as_ref() {
            let pin_ver = semver::Version::parse(&pin.version)
                .map_err(|e| AutoUpgradeError::BadVersion(pin.version.clone(), e))?;
            let latest_ver = semver::Version::parse(&latest.version)
                .map_err(|e| AutoUpgradeError::BadVersion(latest.version.clone(), e))?;
            if latest_ver > pin_ver {
                debug!(
                    pinned = %pin.version,
                    latest = %latest.version,
                    "auto_upgrade::orchestrator: latest past pin; skipping"
                );
                return Ok(OrchestratorOutcome::SkippedPinned {
                    pinned: pin.version.clone(),
                    latest: latest.version.clone(),
                });
            }
        }
        let decision = should_upgrade(&opts.self_version, &latest)?;
        match decision {
            UpgradeDecision::AlreadyAtOrAhead => {
                debug!(
                    self_version = %opts.self_version,
                    latest_version = %latest.version,
                    "auto_upgrade::orchestrator: already at or ahead of latest"
                );
                return Ok(OrchestratorOutcome::SkippedAlreadyAtOrAhead);
            }
            UpgradeDecision::Upgrade => {}
        }

        info!(
            from = %opts.self_version,
            to = %latest.version,
            asset = %latest.asset,
            "auto_upgrade::orchestrator: upgrading"
        );

        // Download tarball to `<canonical>.tar.gz.new`. After
        // verify + extract, the inner binary lands at
        // `<canonical>.new` and atomic_swap renames into place.
        let tarball_path = {
            let mut s = opts.canonical_binary.as_os_str().to_os_string();
            s.push(".tar.gz.new");
            PathBuf::from(s)
        };
        let _digest = download_binary(&latest.asset_url, &tarball_path).await?;

        // Verify the downloaded tarball against the SHA-256 we
        // got from SHA256SUMS. Read bytes back from disk so the
        // verifier doesn't have to share state with the streaming
        // download path. ~15 MiB readback off a fresh page-cached
        // file is negligible vs the network download we just did.
        let bytes = std::fs::read(&tarball_path).map_err(|e| OrchestratorError::ReadBack {
            path: tarball_path.display().to_string(),
            source: e,
        })?;
        verify_sha256(&bytes, &latest.asset_sha256)?;

        // Extract the inner `p2claw` binary from the tarball.
        let temp_binary = {
            let mut s = opts.canonical_binary.as_os_str().to_os_string();
            s.push(".new");
            PathBuf::from(s)
        };
        extract_binary_from_tarball(&tarball_path, &temp_binary)?;

        // Tarball is extracted; remove it now so a partially-failed
        // upgrade doesn't leave staging cruft in the data dir.
        let _ = std::fs::remove_file(&tarball_path);

        atomic_swap(&opts.canonical_binary, &temp_binary)?;

        // Note: service-config drift check + rewrite happens in
        // the new process's post-Healthy-watchdog path, NOT
        // here. Reasoning: the drift-rewrite renders against the
        // NEW binary's `render_unit` (so the unit stays in sync
        // with the binary); doing it pre-restart in the old
        // process would render against the old binary's template
        // — a no-op, or worse, briefly install an old-unit form
        // that mismatches the about-to-run new binary. `cmd_run`
        // runs the drift-check post-watchdog instead.

        // Write the upgrade-in-progress flag BEFORE triggering
        // the restart. If the restart trigger fails or the host
        // crashes mid-restart, the next cold start sees the flag
        // and runs the health check.
        let flag = UpgradeInProgress {
            target_version: latest.version.clone(),
            from_version: opts.self_version.clone(),
            started_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        };
        write_upgrade_in_progress(&opts.data_dir, &flag).map_err(|e| {
            OrchestratorError::FlagWrite {
                data_dir: opts.data_dir.display().to_string(),
                source: e,
            }
        })?;

        info!(
            from = %opts.self_version,
            to = %latest.version,
            "auto_upgrade::orchestrator: triggering supervised restart"
        );
        Ok(finalize_restart(
            &opts.restart_trigger,
            opts.self_version.clone(),
            latest.version,
        ))
    }

    /// Fire the supervised restart trigger and map its result to an
    /// outcome. Split out so the branch is unit-testable without the
    /// full download→swap path.
    ///
    /// - trigger succeeds → `Upgraded`. Under a supervisor the process
    ///   is usually killed before this returns; the CLI `--apply` (a
    ///   separate process) sees it.
    /// - trigger fails → `StagedPendingManualRestart`. The binary is
    ///   already swapped + the in-progress flag written; the ONLY
    ///   thing that failed is the restart itself — almost always
    ///   because there's no service unit to restart (a manually-run
    ///   `p2claw run`, no systemd/launchd). NOT a hard error: the
    ///   upgrade happened, it's staged. The flag stays put so the
    ///   eventual manual restart runs the post-upgrade watchdog
    ///   (health-check + rollback).
    pub(crate) fn finalize_restart(
        restart_trigger: &RestartTrigger,
        from: String,
        to: String,
    ) -> OrchestratorOutcome {
        match restart_trigger() {
            Ok(()) => OrchestratorOutcome::Upgraded { from, to },
            Err(e) => {
                warn!(
                    from = %from,
                    to = %to,
                    error = %e,
                    "auto_upgrade::orchestrator: supervised restart trigger failed \
                     (no service unit?); binary is staged, manual restart required"
                );
                OrchestratorOutcome::StagedPendingManualRestart { from, to }
            }
        }
    }

    /// Default platform-specific restart trigger. macOS uses
    /// `launchctl kickstart -k`; Linux uses
    /// `systemctl --user restart`. Both forms match what
    /// `service::install` writes — the same supervisor that
    /// originally started the agent restarts it.
    pub fn default_restart_trigger() -> RestartTrigger {
        Arc::new(default_restart_trigger_inner)
    }

    #[cfg(target_os = "linux")]
    fn default_restart_trigger_inner() -> std::io::Result<()> {
        let st = std::process::Command::new("systemctl")
            .args(["--user", "restart", "p2claw-agent.service"])
            .status()?;
        if !st.success() {
            return Err(std::io::Error::other(format!(
                "systemctl --user restart failed: {st}"
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn default_restart_trigger_inner() -> std::io::Result<()> {
        // launchctl kickstart -k <target> SIGTERMs the process and
        // launchd's KeepAlive brings it back. Same target shape as
        // `service.rs::target()` — `gui/<uid>/dev.p2claw.agent`.
        // Inline `nix::unistd::Uid::current()` rather than going through
        // `config::current_uid()` because `config` is a binary-only
        // module (declared in main.rs, not lib.rs); this file lives in
        // the lib, so `crate::config::*` errors E0433 on macOS lib
        // builds. The wrapped function is a one-liner — duplicating it
        // here is cheaper than promoting `config` to a pub-lib module.
        let target = format!(
            "gui/{}/dev.p2claw.agent",
            nix::unistd::Uid::current().as_raw()
        );
        let st = std::process::Command::new("launchctl")
            .args(["kickstart", "-k", &target])
            .status()?;
        if !st.success() {
            return Err(std::io::Error::other(format!(
                "launchctl kickstart failed: {st}"
            )));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn default_restart_trigger_inner() -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "auto-upgrade restart trigger not supported on this platform",
        ))
    }

    /// Heuristic: are we running under an OS supervisor? `cmd_run`
    /// uses this to gate whether the hourly orchestrator task
    /// runs — a dev iterating on `cargo run` shouldn't get
    /// auto-upgraded out from under their build. False positives
    /// here are mostly harmless (the orchestrator runs but the
    /// `--check` decision usually says "AlreadyAtOrAhead" for a
    /// dev build); false negatives leave production unsupervised.
    /// We err toward false-negative.
    pub fn running_under_supervisor() -> bool {
        // systemd: INVOCATION_ID is set by the unit invocation.
        if std::env::var_os("INVOCATION_ID").is_some() {
            return true;
        }
        // launchd: XPC_SERVICE_NAME is set when launchd starts a
        // process. Not perfectly specific (some XPC contexts on
        // macOS also set it), but the false-positive surface is
        // tiny.
        if std::env::var_os("XPC_SERVICE_NAME").is_some() {
            return true;
        }
        false
    }
}

pub mod watchdog {
    //! The post-upgrade health check the new process
    //! runs at startup if the upgrade-in-progress flag is
    //! present. Decides Healthy / HealthyCoordUnreachable /
    //! Unhealthy; the caller (cmd_run) maps Unhealthy to
    //! `restore_previous` + clear-flag + non-zero exit (supervisor
    //! restarts the rolled-back binary).

    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use tokio::sync::watch;
    use tracing::{debug, warn};

    use super::CoordHealth;

    /// Inputs to [`post_upgrade_health_check`].
    pub struct HealthCheckOpts {
        /// Path to the agent's local API Unix socket. The watchdog
        /// dials this and reads `GET /v1/identity`; success means
        /// the agent process loaded its identity, started the local
        /// API task, and bound the socket — the load-bearing
        /// "alive and serving" signal.
        pub local_api_socket: PathBuf,
        /// Watch on the coord_conn liveness state. The watchdog
        /// observes this for the bonus signal; absence is
        /// gracefully degraded to `HealthyCoordUnreachable`, NOT
        /// unhealthy. (User's network being weird shouldn't roll
        /// back a working binary.)
        pub coord_health: watch::Receiver<CoordHealth>,
        /// Total budget for the health check. Beyond this we
        /// declare `Unhealthy` and the caller rolls back.
        pub timeout: Duration,
    }

    /// Result of [`post_upgrade_health_check`]. Caller in cmd_run
    /// maps:
    /// - `Healthy` / `HealthyCoordUnreachable` → clear flag,
    ///   continue serving.
    /// - `Unhealthy` → call `restore_previous`, clear flag, exit
    ///   non-zero (supervisor restarts; `.previous` brings up the
    ///   old binary).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HealthOutcome {
        Healthy,
        HealthyCoordUnreachable,
        Unhealthy { reason: String },
    }

    /// Run the post-upgrade health check. Polls the local API for
    /// up to `opts.timeout`; concurrently observes
    /// `opts.coord_health` for the bonus hello_ack signal. Local
    /// API readiness is required for non-Unhealthy outcomes.
    pub async fn post_upgrade_health_check(opts: HealthCheckOpts) -> HealthOutcome {
        let HealthCheckOpts {
            local_api_socket,
            mut coord_health,
            timeout,
        } = opts;

        let deadline = tokio::time::Instant::now() + timeout;

        // Local-API readiness is the load-bearing signal. Poll
        // it on a 250ms interval until success or deadline.
        let local_api_ready = async {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match probe_local_api(&local_api_socket).await {
                    Ok(()) => return,
                    Err(e) => {
                        debug!(
                            error = %e,
                            socket = %local_api_socket.display(),
                            "auto_upgrade::watchdog: local_api probe failed; retrying"
                        );
                    }
                }
            }
        };

        let local_api_outcome = tokio::select! {
            _ = local_api_ready => Ok(()),
            _ = tokio::time::sleep_until(deadline) => Err(
                "local_api never became ready within timeout".to_string(),
            ),
        };

        if let Err(reason) = local_api_outcome {
            warn!(
                reason,
                "auto_upgrade::watchdog: unhealthy — local API failed to come up"
            );
            return HealthOutcome::Unhealthy { reason };
        }

        // Local API came up. Observe coord_health: if already
        // ConnectedHelloAck, return Healthy. Otherwise wait for
        // either a transition to ConnectedHelloAck or the
        // remainder of the budget to elapse.
        if matches!(*coord_health.borrow(), CoordHealth::ConnectedHelloAck) {
            return HealthOutcome::Healthy;
        }
        let coord_remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let coord_wait = async {
            loop {
                if coord_health.changed().await.is_err() {
                    return false; // sender dropped
                }
                if matches!(*coord_health.borrow(), CoordHealth::ConnectedHelloAck) {
                    return true;
                }
            }
        };
        match tokio::time::timeout(coord_remaining, coord_wait).await {
            Ok(true) => HealthOutcome::Healthy,
            _ => {
                debug!(
                    "auto_upgrade::watchdog: local_api ok, coord hello_ack missed window — \
                     gracefully degraded to HealthyCoordUnreachable"
                );
                HealthOutcome::HealthyCoordUnreachable
            }
        }
    }

    /// Dial the local API at `socket` + GET /v1/identity. Returns
    /// `Ok(())` iff the server responded with a 2xx. Used by the
    /// watchdog as the "agent process is alive and serving"
    /// signal — a live HTTP response over the agent's own UDS
    /// proves the process loaded identity, started the local-api
    /// task, and bound the socket.
    async fn probe_local_api(socket: &Path) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        let mut s = UnixStream::connect(socket)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        s.write_all(b"GET /v1/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.map_err(|e| format!("read: {e}"))?;
        let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let first = head.lines().next().unwrap_or("");
        if first.starts_with("HTTP/1.1 2") || first.starts_with("HTTP/1.0 2") {
            Ok(())
        } else {
            Err(format!("non-2xx response: {first}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_latest_release(version: &str) -> LatestRelease {
        // Asset name uses whatever current_platform_asset returns
        // for THIS build's target — keeps tests OS-agnostic.
        let asset = current_platform_asset(version)
            .unwrap_or_else(|| format!("p2claw-v{version}-linux-x86_64.tar.gz"));
        LatestRelease {
            version: version.to_string(),
            asset: asset.clone(),
            asset_url: format!("https://example.test/download/v{version}/{asset}"),
            asset_sha256: [0xAB; 32],
        }
    }

    // ---------- URL builders + repo override ------------------

    #[test]
    fn latest_release_url_for_default_repo() {
        let url = latest_release_url(DEFAULT_RELEASE_REPO);
        assert_eq!(url, "https://github.com/phact/p2claw-skill/releases/latest");
    }

    #[test]
    fn release_asset_url_composes_tag_and_filename() {
        let url = release_asset_url("phact/p2claw-skill", "0.3.0", "SHA256SUMS");
        assert_eq!(
            url,
            "https://github.com/phact/p2claw-skill/releases/download/v0.3.0/SHA256SUMS"
        );
    }

    /// Process-wide lock for env-mutating tests. std env mutation
    /// is process-global + cargo runs tests in parallel, so two
    /// tests touching the same var race. Same shape as the
    /// env-mutex in `priv_drop` + `main`.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_release_repo_honors_env_override() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(RELEASE_REPO_ENV).ok();
        std::env::set_var(RELEASE_REPO_ENV, "my-fork/their-skill");
        assert_eq!(resolve_release_repo(), "my-fork/their-skill");
        match prev {
            Some(v) => std::env::set_var(RELEASE_REPO_ENV, v),
            None => std::env::remove_var(RELEASE_REPO_ENV),
        }
    }

    #[test]
    fn resolve_release_repo_falls_back_to_default_when_env_empty() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(RELEASE_REPO_ENV).ok();
        std::env::set_var(RELEASE_REPO_ENV, "   ");
        assert_eq!(resolve_release_repo(), DEFAULT_RELEASE_REPO);
        std::env::remove_var(RELEASE_REPO_ENV);
        assert_eq!(resolve_release_repo(), DEFAULT_RELEASE_REPO);
        if let Some(v) = prev {
            std::env::set_var(RELEASE_REPO_ENV, v);
        }
    }

    // ---------- redirect-Location parser ----------------------

    #[test]
    fn parse_version_strips_leading_v_from_tag_url() {
        let url = "https://github.com/phact/p2claw-skill/releases/tag/v0.2.0";
        assert_eq!(parse_version_from_release_tag_url(url).unwrap(), "0.2.0");
    }

    #[test]
    fn parse_version_handles_trailing_slash() {
        let url = "https://github.com/phact/p2claw-skill/releases/tag/v0.3.0/";
        assert_eq!(parse_version_from_release_tag_url(url).unwrap(), "0.3.0");
    }

    #[test]
    fn parse_version_errors_when_no_v_prefix() {
        // Pin: GH always emits `v<semver>` for tags. A Location
        // without the `v` is suspicious — refuse rather than
        // silently install whatever's at the URL. Catches a
        // future GH UI change before it silently breaks
        // production fleets.
        let url = "https://github.com/phact/p2claw-skill/releases/tag/0.2.0";
        let err = parse_version_from_release_tag_url(url).unwrap_err();
        assert!(matches!(err, AutoUpgradeError::BadRedirectLocation(_)));
    }

    // ---------- SHA256SUMS parser -----------------------------

    #[test]
    fn parse_sha256sums_handles_gnu_two_space_format() {
        // GNU `sha256sum` emits `<digest>  <filename>` (two
        // spaces). The default what GH Actions' tar/sha256sum
        // produces.
        let body = "\
abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  p2claw-v0.2.0-linux-x86_64.tar.gz
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff  p2claw-v0.2.0-macos-aarch64.tar.gz
";
        let out = parse_sha256sums(body).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.get("p2claw-v0.2.0-linux-x86_64.tar.gz").unwrap()[0],
            0xab
        );
    }

    #[test]
    fn parse_sha256sums_skips_blank_and_comment_lines() {
        let body = "\
# header
\nabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  somefile
\n# trailer\n";
        let out = parse_sha256sums(body).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn parse_sha256sums_rejects_short_digest() {
        // 32-hex-char digest (a SHA-1 length, not SHA-256). Pin
        // length-correctness so a botched release pipeline
        // (e.g., emitting sha1sum output by accident) fails
        // loudly rather than silently accepting.
        let body = "abc  somefile\n";
        let err = parse_sha256sums(body).unwrap_err();
        assert!(matches!(err, AutoUpgradeError::Sha256SumsParse(_)));
    }

    #[test]
    fn parse_sha256sums_rejects_empty_body() {
        let err = parse_sha256sums("").unwrap_err();
        assert!(matches!(err, AutoUpgradeError::Sha256SumsParse(_)));
    }

    // ---------- platform asset selection ----------------------

    #[test]
    fn current_platform_asset_returns_some_on_supported_targets() {
        // This test runs on the host's actual platform — at
        // least one of (linux, macos) × (x86_64, aarch64) must
        // be true for our supported matrix.
        let asset = current_platform_asset("0.2.0");
        if cfg!(any(target_os = "linux", target_os = "macos"))
            && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        {
            assert!(
                asset.is_some(),
                "supported target should yield an asset name"
            );
            let s = asset.unwrap();
            assert!(s.starts_with("p2claw-v0.2.0-"));
            assert!(s.ends_with(".tar.gz"));
        }
    }

    // ---------- decision logic --------------------------------

    #[test]
    fn should_upgrade_returns_upgrade_for_newer_release() {
        let latest = fixture_latest_release("0.2.0");
        let dec = should_upgrade("0.1.0", &latest).unwrap();
        assert_eq!(dec, UpgradeDecision::Upgrade);
    }

    #[test]
    fn should_upgrade_returns_already_at_or_ahead_when_self_matches_or_exceeds() {
        let latest = fixture_latest_release("0.2.0");
        // Equal — already at.
        assert_eq!(
            should_upgrade("0.2.0", &latest).unwrap(),
            UpgradeDecision::AlreadyAtOrAhead
        );
        // Ahead.
        assert_eq!(
            should_upgrade("0.3.0", &latest).unwrap(),
            UpgradeDecision::AlreadyAtOrAhead
        );
    }

    #[test]
    fn should_upgrade_propagates_bad_version_strings() {
        let latest = fixture_latest_release("not-a-version");
        let err = should_upgrade("0.1.0", &latest).unwrap_err();
        assert!(matches!(err, AutoUpgradeError::BadVersion(_, _)), "{err:?}");
    }

    // ---------- SHA-256 verify --------------------------------

    #[test]
    fn verify_sha256_accepts_matching_digest() {
        let payload = b"fake agent tarball bytes";
        let mut h = Sha256::new();
        h.update(payload);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(h.finalize().as_slice());
        verify_sha256(payload, &expected).expect("matching digest must verify");
    }

    #[test]
    fn verify_sha256_rejects_mismatch() {
        let payload = b"fake agent tarball bytes";
        // Off-by-one byte → digest mismatch → error.
        let mut tampered = payload.to_vec();
        tampered[0] ^= 0xFF;
        let mut h = Sha256::new();
        h.update(payload);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(h.finalize().as_slice());
        let err = verify_sha256(&tampered, &expected).unwrap_err();
        assert!(matches!(err, BinaryError::Sha256Mismatch { .. }), "{err:?}");
    }

    // ---------- tarball extraction ----------------------------

    #[test]
    fn extract_binary_from_tarball_finds_top_level_p2claw_entry() {
        // Build a minimal tarball in-memory: gzip(tar(p2claw)).
        let dir = tempfile::tempdir().unwrap();
        let tarball_path = dir.path().join("test.tar.gz");
        let binary_bytes = b"#!/usr/bin/env echo\nfake-agent-binary\n";
        let f = std::fs::File::create(&tarball_path).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut tar_w = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(binary_bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_w
            .append_data(&mut header, "p2claw", &binary_bytes[..])
            .unwrap();
        tar_w.into_inner().unwrap().finish().unwrap();

        let dest = dir.path().join("p2claw-extracted");
        extract_binary_from_tarball(&tarball_path, &dest).expect("extraction must succeed");
        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, binary_bytes);
        // Mode 0755 set post-extract on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "extracted binary must be executable");
        }
    }

    #[test]
    fn extract_binary_from_tarball_errors_when_no_p2claw_entry() {
        // Tarball with only a README — no `p2claw` binary.
        let dir = tempfile::tempdir().unwrap();
        let tarball_path = dir.path().join("test.tar.gz");
        let f = std::fs::File::create(&tarball_path).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut tar_w = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        let body = b"# README\n";
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_w
            .append_data(&mut header, "README.md", &body[..])
            .unwrap();
        tar_w.into_inner().unwrap().finish().unwrap();

        let dest = dir.path().join("p2claw-extracted");
        let err = extract_binary_from_tarball(&tarball_path, &dest).unwrap_err();
        assert!(matches!(err, BinaryError::NoBinaryInTarball), "{err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn download_binary_streams_to_dest_and_returns_sha256() {
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let payload = b"the binary bytes the upgrade would download".repeat(100);
        let payload_clone = payload.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp_head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                payload_clone.len()
            );
            sock.write_all(resp_head.as_bytes()).await.unwrap();
            sock.write_all(&payload_clone).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("agent-new");
        let url = format!("http://{addr}/agent-new");
        let returned_digest = download_binary(&url, &dest).await.expect("download ok");

        // Hash matches what the helper returned.
        let mut h = Sha256::new();
        h.update(&payload);
        let want_digest = h.finalize();
        assert_eq!(returned_digest.as_slice(), want_digest.as_slice());

        // Bytes on disk match the original payload.
        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, payload);
    }

    #[test]
    fn atomic_swap_keeps_previous_and_installs_new() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("agent");
        let new_temp = dir.path().join("agent.new");
        std::fs::write(&canonical, b"old binary").unwrap();
        std::fs::write(&new_temp, b"new binary").unwrap();

        atomic_swap(&canonical, &new_temp).expect("swap ok");

        // canonical now has the new bytes.
        assert_eq!(std::fs::read(&canonical).unwrap(), b"new binary");
        // .previous has the old bytes.
        let previous = canonical.with_extension("previous");
        // Note: with_extension replaces the extension; for a no-
        // extension path like "agent", we get "agent.previous".
        assert_eq!(std::fs::read(&previous).unwrap(), b"old binary");
        // new_temp is gone (renamed into canonical).
        assert!(!new_temp.exists());
    }

    #[test]
    fn atomic_swap_works_when_no_previous_canonical_exists() {
        // First-ever install: no canonical to preserve.
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("agent");
        let new_temp = dir.path().join("agent.new");
        std::fs::write(&new_temp, b"first install").unwrap();
        atomic_swap(&canonical, &new_temp).expect("swap ok");
        assert_eq!(std::fs::read(&canonical).unwrap(), b"first install");
        assert!(!canonical.with_extension("previous").exists());
    }

    #[test]
    fn restore_previous_swaps_back_after_failed_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("agent");
        let new_temp = dir.path().join("agent.new");
        std::fs::write(&canonical, b"working old").unwrap();
        std::fs::write(&new_temp, b"broken new").unwrap();
        atomic_swap(&canonical, &new_temp).unwrap();
        // Pretend the new binary failed to start within the
        // grace window — roll back.
        restore_previous(&canonical).expect("rollback ok");
        // canonical now has the working-old bytes.
        assert_eq!(std::fs::read(&canonical).unwrap(), b"working old");
        // .previous is gone (consumed by the rollback rename).
        assert!(!canonical.with_extension("previous").exists());
    }

    #[test]
    fn restore_previous_errors_when_no_previous_exists() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("agent");
        std::fs::write(&canonical, b"current").unwrap();
        let err = restore_previous(&canonical).expect_err("rollback without .previous must error");
        match err {
            BinaryError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io NotFound, got {other:?}"),
        }
    }

    // ===== upgrade-in-progress flag I/O =====

    #[test]
    fn upgrade_in_progress_flag_roundtrips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let flag = UpgradeInProgress {
            target_version: "0.3.0".into(),
            from_version: "0.2.0".into(),
            started_at_unix: 1_700_000_000,
        };
        write_upgrade_in_progress(dir.path(), &flag).unwrap();
        let got = read_upgrade_in_progress(dir.path()).unwrap();
        assert_eq!(got, Some(flag));
    }

    #[test]
    fn read_upgrade_in_progress_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let got = read_upgrade_in_progress(dir.path()).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn read_upgrade_in_progress_treats_malformed_as_absent() {
        // Operator (or filesystem corruption) leaves a non-JSON
        // file in place — watchdog must not panic; treat as
        // "no upgrade in flight" so cmd_run takes the cold-start
        // path.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(UPGRADE_IN_PROGRESS_FILENAME),
            b"this is not json",
        )
        .unwrap();
        let got = read_upgrade_in_progress(dir.path()).unwrap();
        assert!(got.is_none(), "malformed flag must read as absent");
    }

    #[test]
    fn clear_upgrade_in_progress_is_idempotent_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        // No file present; clear must succeed.
        clear_upgrade_in_progress(dir.path()).unwrap();
    }

    #[test]
    fn clear_upgrade_in_progress_removes_existing() {
        let dir = tempfile::tempdir().unwrap();
        let flag = UpgradeInProgress {
            target_version: "0.3.0".into(),
            from_version: "0.2.0".into(),
            started_at_unix: 0,
        };
        write_upgrade_in_progress(dir.path(), &flag).unwrap();
        assert!(dir.path().join(UPGRADE_IN_PROGRESS_FILENAME).exists());
        clear_upgrade_in_progress(dir.path()).unwrap();
        assert!(!dir.path().join(UPGRADE_IN_PROGRESS_FILENAME).exists());
    }

    // ===== policy =====

    mod policy_tests {
        use crate::auto_upgrade::policy::*;

        #[test]
        fn pin_roundtrips_on_disk() {
            let dir = tempfile::tempdir().unwrap();
            assert!(read_pin(dir.path()).unwrap().is_none());
            let pin = UpgradePin {
                version: "0.3.0".into(),
            };
            write_pin(dir.path(), &pin).unwrap();
            assert_eq!(read_pin(dir.path()).unwrap(), Some(pin));
        }

        #[test]
        fn read_pin_treats_malformed_as_absent() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(PIN_FILENAME), b"not json").unwrap();
            assert!(read_pin(dir.path()).unwrap().is_none());
        }

        #[test]
        fn clear_pin_is_idempotent_on_missing() {
            let dir = tempfile::tempdir().unwrap();
            // No file present; clear succeeds.
            clear_pin(dir.path()).unwrap();
            // Now write + clear + clear again.
            write_pin(
                dir.path(),
                &UpgradePin {
                    version: "0.3.0".into(),
                },
            )
            .unwrap();
            clear_pin(dir.path()).unwrap();
            clear_pin(dir.path()).unwrap();
            assert!(read_pin(dir.path()).unwrap().is_none());
        }

        #[test]
        fn disabled_sentinel_roundtrips() {
            let dir = tempfile::tempdir().unwrap();
            assert!(!is_disabled(dir.path()));
            set_disabled(dir.path()).unwrap();
            assert!(is_disabled(dir.path()));
            // Idempotent: setting again is OK.
            set_disabled(dir.path()).unwrap();
            assert!(is_disabled(dir.path()));
            clear_disabled(dir.path()).unwrap();
            assert!(!is_disabled(dir.path()));
            // Idempotent: clearing again is OK.
            clear_disabled(dir.path()).unwrap();
            assert!(!is_disabled(dir.path()));
        }

        /// Integration: the disabled sentinel short-circuits the
        /// orchestrator before any network IO. Locks the contract
        /// that `set_disabled` → `run_once` returns
        /// `SkippedDisabled` without dialing the release CDN. The
        /// `release_repo` is a deliberately bogus value
        /// (`localhost:1` would fail-fast); the test passes IFF
        /// `run_once` short-circuits before even constructing the
        /// reqwest client. If a future refactor moves the disabled
        /// check below the release lookup, this test fails with
        /// a `Manifest(...)` orchestrator error instead of
        /// `Ok(SkippedDisabled)`.
        #[tokio::test]
        async fn run_once_short_circuits_when_disabled_without_network_io() {
            use crate::auto_upgrade::orchestrator::{
                run_once, OrchestratorOpts, OrchestratorOutcome,
            };
            use std::sync::Arc;

            let dir = tempfile::tempdir().unwrap();
            set_disabled(dir.path()).unwrap();

            let opts = OrchestratorOpts {
                // Bogus repo — `fetch_latest_release` would error,
                // but we never get there.
                release_repo: "this-org/does-not-exist-and-must-not-be-fetched".into(),
                self_version: "0.0.1".into(),
                canonical_binary: dir.path().join("p2claw"),
                data_dir: dir.path().to_path_buf(),
                restart_trigger: Arc::new(|| {
                    panic!("restart_trigger must not fire on a disabled cycle")
                }),
            };
            let outcome = run_once(&opts).await.expect("run_once succeeds");
            assert_eq!(outcome, OrchestratorOutcome::SkippedDisabled);
        }

        #[test]
        fn finalize_restart_success_is_upgraded() {
            use crate::auto_upgrade::orchestrator::{finalize_restart, OrchestratorOutcome};
            use std::sync::Arc;

            let trigger: crate::auto_upgrade::orchestrator::RestartTrigger = Arc::new(|| Ok(()));
            let outcome = finalize_restart(&trigger, "0.10.6".into(), "0.10.7".into());
            assert_eq!(
                outcome,
                OrchestratorOutcome::Upgraded {
                    from: "0.10.6".into(),
                    to: "0.10.7".into(),
                }
            );
        }

        #[test]
        fn finalize_restart_failure_is_staged_pending_manual_restart() {
            // A failing restart trigger (e.g. `systemctl restart` on a
            // box with no unit) must NOT surface as a hard error — the
            // binary is already staged. It maps to
            // StagedPendingManualRestart so the CLI can tell the
            // operator to restart the daemon.
            use crate::auto_upgrade::orchestrator::{finalize_restart, OrchestratorOutcome};
            use std::sync::Arc;

            let trigger: crate::auto_upgrade::orchestrator::RestartTrigger = Arc::new(|| {
                Err(std::io::Error::other(
                    "systemctl --user restart failed: no such unit",
                ))
            });
            let outcome = finalize_restart(&trigger, "0.10.6".into(), "0.10.7".into());
            assert_eq!(
                outcome,
                OrchestratorOutcome::StagedPendingManualRestart {
                    from: "0.10.6".into(),
                    to: "0.10.7".into(),
                }
            );
        }
    }

    // ===== watchdog =====

    mod watchdog_tests {
        use super::*;
        use crate::auto_upgrade::watchdog::*;
        use crate::auto_upgrade::CoordHealth;
        use std::sync::Arc;
        use tokio::sync::watch;

        /// Spin up a minimal local-API stand-in over a Unix
        /// socket. Replies "HTTP/1.1 200 OK" with a tiny body to
        /// every connection. Used by the watchdog tests so we
        /// don't need to drag the full LocalApi in.
        async fn spawn_loopback_local_api(socket: PathBuf) -> tokio::task::JoinHandle<()> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::UnixListener;
            let listener = UnixListener::bind(&socket).expect("bind UDS");
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        let _ = sock.read(&mut buf).await;
                        let body = br#"{"peer_id":"test","registered":true}"#;
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(body).await;
                        let _ = sock.shutdown().await;
                    });
                }
            })
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn returns_healthy_when_local_api_up_and_coord_helloack() {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("agent.sock");
            let _api = spawn_loopback_local_api(sock.clone()).await;
            // Race: give the listener a moment to bind.
            for _ in 0..20 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let (tx, rx) = watch::channel(CoordHealth::ConnectedHelloAck);
            let _keep_tx = Arc::new(tx);
            let outcome = post_upgrade_health_check(HealthCheckOpts {
                local_api_socket: sock,
                coord_health: rx,
                timeout: Duration::from_secs(5),
            })
            .await;
            assert_eq!(outcome, HealthOutcome::Healthy);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn returns_healthy_when_coord_transitions_to_helloack_during_wait() {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("agent.sock");
            let _api = spawn_loopback_local_api(sock.clone()).await;
            for _ in 0..20 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let (tx, rx) = watch::channel(CoordHealth::Connecting);
            // After a delay, transition to ConnectedHelloAck.
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = tx.send(CoordHealth::ConnectedHelloAck);
                // Keep the sender alive past the watchdog
                // observation so `coord_health.changed()` doesn't
                // resolve as "sender dropped".
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
            let outcome = post_upgrade_health_check(HealthCheckOpts {
                local_api_socket: sock,
                coord_health: rx,
                timeout: Duration::from_secs(5),
            })
            .await;
            assert_eq!(outcome, HealthOutcome::Healthy);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn returns_healthy_coord_unreachable_when_only_local_api_up() {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("agent.sock");
            let _api = spawn_loopback_local_api(sock.clone()).await;
            for _ in 0..20 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // coord_health stays at Connecting forever — keep tx
            // alive so `changed()` doesn't return as
            // "sender dropped" (which would make the test flaky).
            let (tx, rx) = watch::channel(CoordHealth::Connecting);
            let _keep_tx = Arc::new(tx);
            let outcome = post_upgrade_health_check(HealthCheckOpts {
                local_api_socket: sock,
                coord_health: rx,
                // Short budget so the test doesn't actually wait
                // 60s — coord-unreachable path needs the budget
                // to elapse.
                timeout: Duration::from_millis(800),
            })
            .await;
            assert_eq!(outcome, HealthOutcome::HealthyCoordUnreachable);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn returns_unhealthy_when_local_api_never_comes_up() {
            // No local-API server bound at the socket path. The
            // watchdog must time out + return Unhealthy.
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("agent.sock");
            let (tx, rx) = watch::channel(CoordHealth::ConnectedHelloAck);
            let _keep_tx = Arc::new(tx);
            let outcome = post_upgrade_health_check(HealthCheckOpts {
                local_api_socket: sock,
                coord_health: rx,
                timeout: Duration::from_millis(500),
            })
            .await;
            match outcome {
                HealthOutcome::Unhealthy { reason } => {
                    assert!(
                        reason.contains("local_api"),
                        "reason should mention local_api: {reason}"
                    );
                }
                other => panic!("expected Unhealthy, got {other:?}"),
            }
        }
    }
}
