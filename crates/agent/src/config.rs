//! Filesystem-path resolution for the agent.
//!
//! Produces the on-disk paths for the identity key, persisted
//! registration state, and the Unix socket used by the local API.
//! Supports Linux and macOS only; Windows builds are blocked in
//! `main.rs`.

use std::env;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("$HOME is not set — cannot resolve default data directory")]
    MissingHome,
}

/// All on-disk paths the agent needs.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Paths {
    pub fn identity_key(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    pub fn agent_state(&self) -> PathBuf {
        self.data_dir.join("agent.state")
    }

    pub fn agent_sock(&self) -> PathBuf {
        self.runtime_dir.join("agent.sock")
    }
}

/// Resolve paths from the environment. Allows per-field overrides
/// (useful for tests).
///
/// Explicit overrides (checked first, before any XDG / HOME logic):
/// - `P2CLAW_AGENT_DATA_DIR` — absolute path used verbatim as the
///   data dir (holds `identity.key`, `agent.state`).
/// - `P2CLAW_AGENT_RUNTIME_DIR` — absolute path used verbatim as the
///   runtime dir (holds `agent.sock`).
///
/// These are the knobs e2e harnesses (Playwright, test-in-process)
/// use to redirect every agent artifact into a fresh tempdir without
/// touching the user's real `$XDG_DATA_HOME/p2claw`.
pub fn resolve() -> Result<Paths, ConfigError> {
    Ok(Paths {
        data_dir: data_dir()?,
        runtime_dir: runtime_dir(),
    })
}

/// Override the base directories (test-only).
#[cfg(test)]
pub fn with_overrides(data_dir: Option<PathBuf>, runtime_dir: Option<PathBuf>) -> Paths {
    Paths {
        data_dir: data_dir.unwrap_or_else(|| PathBuf::from("/tmp/p2claw-test/data")),
        runtime_dir: runtime_dir.unwrap_or_else(|| PathBuf::from("/tmp/p2claw-test/run")),
    }
}

#[cfg(target_os = "linux")]
fn data_dir() -> Result<PathBuf, ConfigError> {
    if let Ok(v) = env::var("P2CLAW_AGENT_DATA_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("p2claw"));
        }
    }
    let home = home_dir().ok_or(ConfigError::MissingHome)?;
    Ok(home.join(".local/share/p2claw"))
}

#[cfg(target_os = "macos")]
fn data_dir() -> Result<PathBuf, ConfigError> {
    if let Ok(v) = env::var("P2CLAW_AGENT_DATA_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let home = home_dir().ok_or(ConfigError::MissingHome)?;
    Ok(home.join("Library/Application Support/p2claw"))
}

/// Resolve the user's home directory with a passwd-based fallback
/// when `$HOME` isn't in the environment. Mirrors glibc's own
/// resolution chain: `getenv("HOME")` first; if that's missing or
/// empty, `getpwuid_r(geteuid())->pw_dir`.
///
/// Why the fallback matters: systemd services start with NO `$HOME`
/// in the environment by default (`systemd.exec(5)` —
/// `Environment=` is empty unless explicitly populated, and `HOME`
/// isn't on the inherited list). cron jobs hit the same gap.
/// Without this fallback, anyone running `p2claw` under those
/// supervisors would error out on every subcommand because
/// `config::resolve()` is called unconditionally up front (see
/// `main.rs::main`) — `p2claw service install --system` from a
/// systemd oneshot would hit `MissingHome` before the install
/// logic ever ran.
///
/// `nix::unistd::User::from_uid` returns `Ok(None)` for "no passwd
/// entry" and `Err(_)` for "passwd lookup failed" (most commonly
/// `EIO` on container hosts with weird /etc/passwd layouts). Both
/// collapse to `None` here — the caller surfaces `MissingHome`
/// either way.
fn home_dir() -> Option<PathBuf> {
    if let Ok(h) = env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    let uid = nix::unistd::Uid::effective();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.dir)
}

/// Runtime (Unix-socket) directory.
///
/// Resolution order (Linux):
/// 1. `P2CLAW_AGENT_RUNTIME_DIR` (verbatim) — explicit override,
///    used by tests + by operators with non-default layouts.
/// 2. `$XDG_RUNTIME_DIR/p2claw` when set — user-scope systemd
///    sets this to `/run/user/<uid>` automatically; `p2claw run`
///    under the user-scope LaunchAgent picks it up.
/// 3. `/run/p2claw` when running as root AND that path exists —
///    the system-scope LaunchDaemon's unit file declares
///    `RuntimeDirectory=p2claw`, which makes systemd create
///    `/run/p2claw` (mode 0755, owned by the unit's User=) at
///    service start + tear it down at stop. This is the
///    canonical systemd location for system-scope runtime
///    sockets, and it crucially survives `PrivateTmp=true` (the
///    unit's `/run` is mounted from the host so the socket is
///    visible to non-namespaced clients like CLI tools that
///    didn't start with the unit). The dir-must-exist gate
///    means `p2claw register` (which runs BEFORE
///    `install --system` mints the runtime dir) doesn't pick
///    this path on a fresh host.
/// 4. `/tmp/p2claw-$UID` as the final fallback.
///
/// macOS: always `/tmp/p2claw-$UID` (avoids the `sun_path`
/// length cap under `~/Library/...`).
fn runtime_dir() -> PathBuf {
    if let Ok(v) = env::var("P2CLAW_AGENT_RUNTIME_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("p2claw");
            }
        }
        // The system-scope install's unit file
        // declares `RuntimeDirectory=p2claw`, which materialises
        // `/run/p2claw` at service-start and tears it down at
        // stop. Use it when present + we're root. CLI clients
        // (`p2claw expose` etc.) hit the same code path so they
        // resolve the same socket path the daemon's listening on.
        // PrivateTmp=true on the unit doesn't affect /run, so
        // the socket survives the agent's tmp-namespace
        // hardening.
        if current_uid() == 0 && std::path::Path::new("/run/p2claw").is_dir() {
            return PathBuf::from("/run/p2claw");
        }
    }
    let uid = current_uid();
    PathBuf::from(format!("/tmp/p2claw-{uid}"))
}

/// Our effective UID. Wraps `getuid(2)` through the `nix` crate so
/// the workspace's `unsafe_code = "forbid"` stays in effect.
pub fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

/// Best-effort guard against a `sun_path` overflow — the kernel limit
/// is ~108 on Linux and 104 on macOS/BSD.
pub fn check_sock_path(path: &Path) -> Result<(), std::io::Error> {
    const SUN_PATH_MAX: usize = 100;
    if path.as_os_str().len() >= SUN_PATH_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "agent socket path {} is too long for a unix-domain socket \
                 (len {}, max {SUN_PATH_MAX})",
                path.display(),
                path.as_os_str().len(),
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env-mutating tests serialize on this — cargo runs `#[test]`
    /// functions concurrently by default, and `env::set_var` is a
    /// process-wide effect.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn paths_suffixes_are_stable() {
        let p = with_overrides(
            Some(PathBuf::from("/opt/data")),
            Some(PathBuf::from("/run/me")),
        );
        assert_eq!(p.identity_key(), PathBuf::from("/opt/data/identity.key"));
        assert_eq!(p.agent_state(), PathBuf::from("/opt/data/agent.state"));
        assert_eq!(p.agent_sock(), PathBuf::from("/run/me/agent.sock"));
    }

    #[test]
    fn sock_path_overflow_rejected() {
        let long = "x".repeat(200);
        assert!(check_sock_path(Path::new(&long)).is_err());
    }

    #[test]
    fn sock_path_short_ok() {
        assert!(check_sock_path(Path::new("/tmp/p2claw-1000/agent.sock")).is_ok());
    }

    #[test]
    fn current_uid_is_plausible() {
        // Nothing to compare against on arbitrary CI, but the call
        // must not panic and must return something.
        let _ = current_uid();
    }

    #[test]
    fn data_dir_env_override_wins_over_xdg() {
        let _g = ENV_LOCK.lock().unwrap();
        // Unset first so a previous test's leftover doesn't poison us.
        env::remove_var("P2CLAW_AGENT_DATA_DIR");
        env::remove_var("XDG_DATA_HOME");
        env::set_var("XDG_DATA_HOME", "/tmp/xdg-should-lose");
        env::set_var("P2CLAW_AGENT_DATA_DIR", "/tmp/p2claw-e2e/data");
        let got = data_dir().unwrap();
        env::remove_var("P2CLAW_AGENT_DATA_DIR");
        env::remove_var("XDG_DATA_HOME");
        assert_eq!(got, PathBuf::from("/tmp/p2claw-e2e/data"));
    }

    #[test]
    fn data_dir_env_override_empty_is_ignored() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("P2CLAW_AGENT_DATA_DIR");
        env::set_var("P2CLAW_AGENT_DATA_DIR", "");
        // Must not short-circuit to empty path; falls through.
        // Requires at least HOME for the fallback to succeed.
        if env::var("HOME").is_ok() {
            let got = data_dir().unwrap();
            assert_ne!(got, PathBuf::from(""));
        }
        env::remove_var("P2CLAW_AGENT_DATA_DIR");
    }

    /// systemd services run with NO `$HOME` in their environment,
    /// and the install scaffolding gets invoked from a systemd
    /// `Type=oneshot`; without the passwd fallback `data_dir()`
    /// would `MissingHome`-error before any subcommand-specific
    /// logic ran. Pin the fallback so a future env-rewrite doesn't
    /// re-introduce the regression.
    #[test]
    fn data_dir_falls_back_to_passwd_when_home_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        // Strip every var the resolver checks before $HOME so the
        // fallback path is the only one left.
        let prior_home = env::var_os("HOME");
        let prior_xdg = env::var_os("XDG_DATA_HOME");
        let prior_override = env::var_os("P2CLAW_AGENT_DATA_DIR");
        env::remove_var("HOME");
        env::remove_var("XDG_DATA_HOME");
        env::remove_var("P2CLAW_AGENT_DATA_DIR");

        let got = data_dir();

        // Restore env BEFORE asserting so a panic doesn't leak
        // the wiped state to the next test.
        if let Some(v) = prior_home {
            env::set_var("HOME", v);
        }
        if let Some(v) = prior_xdg {
            env::set_var("XDG_DATA_HOME", v);
        }
        if let Some(v) = prior_override {
            env::set_var("P2CLAW_AGENT_DATA_DIR", v);
        }

        // Cargo test environments always run as a uid with a
        // passwd entry (uid 0 / a normal user dev box). The
        // fallback should yield SOMETHING-shaped: a non-empty
        // path ending in the per-OS suffix.
        let path = got.expect(
            "data_dir() should fall back to getpwuid when $HOME is unset \
             — without this, systemd-supervised invocations of `p2claw` \
             error out on every subcommand.",
        );
        let path_str = path.display().to_string();
        assert!(
            !path_str.is_empty(),
            "passwd fallback returned an empty path: {path:?}"
        );
        // The suffix is per-OS; assert the right one ends the path.
        #[cfg(target_os = "linux")]
        assert!(
            path_str.ends_with("/.local/share/p2claw"),
            "linux fallback should append `.local/share/p2claw`, got: {path_str}"
        );
        #[cfg(target_os = "macos")]
        assert!(
            path_str.ends_with("/Library/Application Support/p2claw"),
            "macos fallback should append `Library/Application Support/p2claw`, got: {path_str}"
        );
    }

    #[test]
    fn home_dir_helper_returns_some_under_normal_passwd_env() {
        // The fallback's load-bearing piece — getpwuid working at
        // all. If this test fails on a real machine, the docker-
        // systemd e2e + every systemd-supervised invocation also
        // fails, so it's worth its own assertion.
        let _g = ENV_LOCK.lock().unwrap();
        let prior_home = env::var_os("HOME");
        env::remove_var("HOME");
        let got = home_dir();
        if let Some(v) = prior_home {
            env::set_var("HOME", v);
        }
        let path = got.expect(
            "getpwuid fallback returned None — passwd lookup failed \
             for the test runner's uid. Check /etc/passwd integrity \
             on this host.",
        );
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn runtime_dir_env_override_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var("P2CLAW_AGENT_RUNTIME_DIR");
        env::set_var("P2CLAW_AGENT_RUNTIME_DIR", "/tmp/p2claw-e2e/run");
        let got = runtime_dir();
        env::remove_var("P2CLAW_AGENT_RUNTIME_DIR");
        assert_eq!(got, PathBuf::from("/tmp/p2claw-e2e/run"));
    }
}
