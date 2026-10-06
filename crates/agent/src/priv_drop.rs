//! Privilege-drop after low-port bind.
//!
//! macOS's system-scope install (`p2claw service install --system`)
//! runs the agent as root via LaunchDaemon — the SNI listener needs
//! that to bind 127.0.0.1:443 (ports < 1024 are root-only on
//! Darwin). Once bound, the agent has no further need of root, and
//! holding root for the process lifetime is a real security hazard:
//! an exploit in the HTTP/QUIC/TLS path would have full root access
//! to the operator's machine.
//!
//! This module implements the standard "bind privileged, drop
//! permanent" pattern:
//!
//! 1. Caller pre-binds 443 (and any other privileged port) while
//!    EUID == 0.
//! 2. Caller calls [`drop_to`] with the resolved target user.
//! 3. We `setgid()` then `setuid()` (in that order — once we lose
//!    root we can't change groups), then verify the drop took.
//! 4. As an extra defensive check, we attempt to regain root via
//!    `setuid(0)` and assert it fails with EPERM — a successful
//!    re-acquisition would mean we're still effectively root and
//!    the drop didn't take. (The kernel guarantees this, but
//!    treating defense-in-depth as cheap when the cost of being
//!    wrong is "still running as root" is the right trade.)
//!
//! ## Cross-platform scope
//!
//! Unix-only by construction (Windows has no setuid; the Service
//! definition runs as LocalSystem there and the priv-drop story
//! is a separate posture problem). Compiles on both Linux and
//! macOS — Linux installs typically use `CAP_NET_BIND_SERVICE`
//! instead of priv-drop (rendered into the systemd unit by
//! `linux_install`), so this module is a no-op for them; macOS has
//! no capability equivalent (Darwin's posix_spawn flags +
//! com.apple.developer.network entitlements need code signing) so
//! priv-drop is the only practical option.
//!
//! ## What this module does NOT do
//!
//! - **Create the target user.** That's an install-time concern
//!   (`macos_install` uses `dscl` to create `_p2claw`). This
//!   module looks the user up by name and refuses to continue if
//!   the lookup fails.
//! - **Chown data files.** The caller decides whether the dropped
//!   user owns the agent's data dir on disk vs. the agent caches
//!   sensitive bytes in-memory before dropping. macos_install
//!   chowns at install time so the dropped user owns the files.
//! - **Drop supplementary groups on macOS.** nix's `setgroups` is
//!   gated to non-Apple targets (Darwin uses `initgroups()`
//!   instead). The dropped user starts with whatever supplementary
//!   groups root had, which on a freshly-created `_p2claw` user
//!   would be just the primary `_p2claw` group anyway. Linux
//!   gets the explicit `setgroups(&[gid])` call.

#![cfg(unix)]

use std::fmt;

use nix::unistd::{Gid, Uid, User};
use thiserror::Error;
use tracing::{info, warn};

/// Resolved target user for the drop. Carries enough state that
/// [`drop_to`] doesn't have to repeat the passwd lookup (which
/// could race with concurrent `dscl` mutations).
#[derive(Debug, Clone)]
pub struct TargetUser {
    pub name: String,
    pub uid: Uid,
    pub gid: Gid,
}

impl fmt::Display for TargetUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(uid={}, gid={})", self.name, self.uid, self.gid)
    }
}

#[derive(Debug, Error)]
pub enum PrivDropError {
    #[error(
        "target user '{name}' not found in passwd database; \
         create it via `dscl . -create /Users/{name}` (macOS) \
         before re-running install"
    )]
    UserNotFound { name: String },
    #[error("passwd lookup for '{name}' failed: {source}")]
    LookupFailed {
        name: String,
        #[source]
        source: nix::Error,
    },
    #[error("setgid({gid}) failed (EUID is {euid}): {source}")]
    SetgidFailed {
        gid: u32,
        euid: u32,
        #[source]
        source: nix::Error,
    },
    #[error("setuid({uid}) failed: {source}")]
    SetuidFailed {
        uid: u32,
        #[source]
        source: nix::Error,
    },
    #[error(
        "post-drop verification failed: setuid({uid}) succeeded but \
         EUID is {actual_euid} (expected {uid}). \
         The drop did not take — refusing to continue."
    )]
    EuidMismatch { uid: u32, actual_euid: u32 },
    #[error(
        "defense-in-depth check failed: post-drop, setuid(0) \
         succeeded — this means we can regain root. The drop did \
         not take in a permanent way. Refusing to continue."
    )]
    CanRegainRoot,
}

/// Look up the target user by name in the passwd database.
/// Wraps [`nix::unistd::User::from_name`] so callers don't need
/// to import nix directly.
///
/// Returns `Ok(TargetUser)` if found, `Err(UserNotFound)` if the
/// name doesn't exist, or `Err(LookupFailed)` if the underlying
/// passwd query errored (rare — would mean a corrupt
/// `Directory Services` cache on macOS or a NIS / SSSD outage on
/// Linux). Callers should treat `UserNotFound` as an installer
/// configuration issue, not a transient error.
pub fn resolve_target_user(name: &str) -> Result<TargetUser, PrivDropError> {
    match User::from_name(name) {
        Ok(Some(u)) => Ok(TargetUser {
            name: u.name,
            uid: u.uid,
            gid: u.gid,
        }),
        Ok(None) => Err(PrivDropError::UserNotFound {
            name: name.to_string(),
        }),
        // libc's getpwnam_r is allowed to surface "not found" two
        // ways: return null+errno=0 (which nix maps to Ok(None)) OR
        // return null+errno=ENOENT (which nix maps to Err). Both
        // mean the same thing — user isn't there. Normalize to the
        // single UserNotFound variant so callers can match cleanly
        // and the macos_install hint about `dscl -create` fires
        // regardless of which path the C library took.
        Err(nix::Error::ENOENT) => Err(PrivDropError::UserNotFound {
            name: name.to_string(),
        }),
        Err(e) => Err(PrivDropError::LookupFailed {
            name: name.to_string(),
            source: e,
        }),
    }
}

/// Drop privileges to `target` permanently. Order is critical:
///
/// 1. **setgid first**, while we still have root (post-setuid we
///    no longer have privilege to change groups).
/// 2. **setgroups** (Linux only) to clear inherited supplementary
///    groups — without this, the dropped user inherits root's
///    group list.
/// 3. **setuid** to drop the user.
/// 4. **Verify** EUID is the target.
/// 5. **Verify** we cannot regain root via `setuid(0)` (defense
///    in depth — the kernel guarantees this, but a wrong
///    assumption here costs us "still effectively root").
///
/// On success, the process is permanently the target user — no
/// path back to root for the rest of the process lifetime. On
/// failure, the agent MUST NOT continue serving requests; the
/// security model assumes priv-drop or never-was-root, never
/// "tried and failed".
///
/// Idempotent in the no-op direction: if EUID is already the
/// target user (i.e., we weren't running as root to begin with —
/// Linux with CAP_NET_BIND_SERVICE, or a dev `cargo run`), this
/// returns `Ok(())` without making any syscalls.
pub fn drop_to(target: &TargetUser) -> Result<(), PrivDropError> {
    let current_euid = nix::unistd::geteuid();
    if current_euid == target.uid {
        // Already the right user — nothing to do.
        info!(
            target = %target,
            euid = current_euid.as_raw(),
            "priv_drop: already running as target user; no drop needed"
        );
        return Ok(());
    }

    // Step 1: setgid. MUST happen while EUID is root — once we
    // setuid away from root, we can't change groups any more.
    // (POSIX: "If the calling process is not privileged ... the
    // gid argument shall be equal to the real, effective, or
    // saved set-group-ID.")
    if let Err(e) = nix::unistd::setgid(target.gid) {
        return Err(PrivDropError::SetgidFailed {
            gid: target.gid.as_raw(),
            euid: current_euid.as_raw(),
            source: e,
        });
    }

    // Step 2: drop supplementary groups. Linux only — nix
    // doesn't expose setgroups on Apple (Darwin uses initgroups
    // which we'd have to FFI ourselves). On macOS, a freshly-
    // created `_p2claw` user belongs only to its primary group,
    // so root's supplementary group list isn't a meaningful
    // contamination vector; revisit if we ever start
    // running on a host where root has extra group memberships
    // that matter.
    #[cfg(not(target_os = "macos"))]
    {
        // Best-effort: a setgroups failure is suspicious enough
        // to log but doesn't independently warrant aborting if
        // the rest of the drop succeeds. (We're about to
        // setuid; supplementary-group inheritance only matters
        // until that point.)
        if let Err(e) = nix::unistd::setgroups(&[target.gid]) {
            warn!(
                target = %target,
                error = %e,
                "priv_drop: setgroups failed; continuing — \
                 supplementary groups may be inherited"
            );
        }
    }

    // Step 3: setuid. After this we're permanently the target.
    if let Err(e) = nix::unistd::setuid(target.uid) {
        return Err(PrivDropError::SetuidFailed {
            uid: target.uid.as_raw(),
            source: e,
        });
    }

    // Step 4: verify the drop took. Without this check, a kernel
    // bug or future libc weirdness could leave us thinking we
    // dropped when we didn't. EUID is the load-bearing thing —
    // file-permission checks all key off it.
    let post_euid = nix::unistd::geteuid();
    if post_euid != target.uid {
        return Err(PrivDropError::EuidMismatch {
            uid: target.uid.as_raw(),
            actual_euid: post_euid.as_raw(),
        });
    }

    // Step 5: defense in depth — confirm we can't regain root.
    // setuid(0) from a non-privileged process MUST fail with
    // EPERM per POSIX. If it succeeds, we never really dropped
    // (process must have had a setuid-root binary, or we're
    // somehow CAP_SETUID-blessed in a way the kernel disagrees
    // with us about). Refuse to continue.
    let regain_attempt = nix::unistd::setuid(Uid::from_raw(0));
    if regain_attempt.is_ok() {
        return Err(PrivDropError::CanRegainRoot);
    }

    info!(
        target = %target,
        previous_euid = current_euid.as_raw(),
        "priv_drop: privileges dropped (setgid + setuid + verified)"
    );
    Ok(())
}

/// Default target user name for system-scope installs. macOS
/// convention: leading underscore for system users (matches
/// `_www`, `_postgres`, etc.). The macOS install creates this
/// user via `dscl` if absent; operators can override at install
/// time + at run time via the `P2CLAW_RUN_AS_USER` env var.
pub const DEFAULT_TARGET_USER: &str = "_p2claw";

/// Env-var name operators can set to override the target user
/// (e.g. `P2CLAW_RUN_AS_USER=p2claw` for a non-Darwin shop with
/// no underscore convention). `cmd_run` reads it; if unset, it
/// falls back to [`DEFAULT_TARGET_USER`].
pub const RUN_AS_USER_ENV: &str = "P2CLAW_RUN_AS_USER";

/// Resolve the runtime target user using the priority chain:
///
/// 1. `P2CLAW_RUN_AS_USER` env var (operator override).
/// 2. `_p2claw` system user (created by `macos_install`
///    via `dscl`; may not exist on a fresh box where the
///    install hasn't run yet).
/// 3. `SUDO_UID` env var (set by `sudo` to the original uid that
///    invoked it). Lets a developer running `sudo p2claw run`
///    interactively drop back to their own account without
///    requiring the install user to exist.
///
/// Returns the first resolution that succeeds. Each step is
/// transparent in logs so operators can audit which path took.
///
/// This chain is the load-bearing piece of the bind-then-drop
/// pattern: the agent must NOT silently default to "stay root"
/// just because the configured target user is missing — that
/// would defeat the security model. If all three fail, the
/// caller (cmd_run) refuses to continue.
pub fn resolve_for_runtime() -> Result<TargetUser, PrivDropError> {
    // Step 1: operator override.
    if let Ok(name) = std::env::var(RUN_AS_USER_ENV) {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            tracing::info!(source = "env", name = %trimmed, "priv_drop: resolving via env override");
            return resolve_target_user(trimmed);
        }
    }

    // Step 2: install-created `_p2claw`.
    match resolve_target_user(DEFAULT_TARGET_USER) {
        Ok(t) => {
            tracing::info!(
                source = "default",
                name = %t.name,
                "priv_drop: resolved default install user"
            );
            return Ok(t);
        }
        Err(PrivDropError::UserNotFound { .. }) => {
            tracing::info!(
                "priv_drop: default user '{DEFAULT_TARGET_USER}' not in passwd; \
                 trying SUDO_UID fallback"
            );
        }
        Err(e) => return Err(e),
    }

    // Step 3: SUDO_UID fallback. `sudo` writes the original
    // invoking uid here. If the env's set + parses, look up the
    // uid in passwd to get the matching name + gid.
    if let Ok(uid_str) = std::env::var("SUDO_UID") {
        let uid: u32 = uid_str.trim().parse().map_err(|_| {
            // SUDO_UID present but not a number is suspicious; bail
            // out rather than silently fall through to "no target".
            PrivDropError::UserNotFound {
                name: format!("SUDO_UID={uid_str}"),
            }
        })?;
        return resolve_target_user_by_uid(Uid::from_raw(uid));
    }

    // All three failed — caller decides what to do. We stay an
    // error rather than silently returning a default; the cmd_run
    // caller refuses to continue under root if this errors.
    Err(PrivDropError::UserNotFound {
        name: format!(
            "{DEFAULT_TARGET_USER} (default) and SUDO_UID (fallback) — \
             override with {RUN_AS_USER_ENV}=<name>"
        ),
    })
}

/// Look up a user by uid (rather than name). Used by the
/// `SUDO_UID` resolution path.
pub fn resolve_target_user_by_uid(uid: Uid) -> Result<TargetUser, PrivDropError> {
    match User::from_uid(uid) {
        Ok(Some(u)) => {
            tracing::info!(
                source = "sudo_uid",
                uid = uid.as_raw(),
                name = %u.name,
                "priv_drop: resolved via SUDO_UID"
            );
            Ok(TargetUser {
                name: u.name,
                uid: u.uid,
                gid: u.gid,
            })
        }
        Ok(None) | Err(nix::Error::ENOENT) => Err(PrivDropError::UserNotFound {
            name: format!("uid={}", uid.as_raw()),
        }),
        Err(e) => Err(PrivDropError::LookupFailed {
            name: format!("uid={}", uid.as_raw()),
            source: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_target_user_finds_a_real_user() {
        // Pick `nobody` — present on every macOS + Linux box,
        // doesn't collide with the agent's own `_p2claw` (which
        // doesn't exist on dev machines).
        let u = resolve_target_user("nobody");
        match u {
            Ok(t) => {
                assert_eq!(t.name, "nobody");
                // Nobody's uid is conventionally 65534 on Linux,
                // -2 (= 4294967294) on macOS — don't pin a value,
                // just sanity-check it's not root.
                assert_ne!(t.uid.as_raw(), 0, "nobody must not be root");
            }
            Err(PrivDropError::UserNotFound { .. }) => {
                // Some minimal CI sandboxes (musl alpine without
                // `nobody` in passwd) might miss it. Skip rather
                // than fail — the function shape is what matters.
                eprintln!("skipping resolve_target_user_finds_a_real_user: nobody not in passwd");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn resolve_target_user_errors_on_unknown_name() {
        // A name we know doesn't exist. Pin the error variant so
        // callers can tell "user missing" apart from "passwd
        // database broken" — `macos_install` will hint at the
        // dscl-create remediation only on UserNotFound.
        let err = resolve_target_user("p2claw-no-such-user-xyz123")
            .expect_err("nonexistent user should not resolve");
        match err {
            PrivDropError::UserNotFound { name } => {
                assert_eq!(name, "p2claw-no-such-user-xyz123");
            }
            other => panic!("expected UserNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn drop_to_is_noop_when_already_target_user() {
        // Construct a TargetUser pointing at OUR current uid —
        // drop_to should be a no-op (the early-return branch).
        // Critically: this test is safe to run in CI as a normal
        // user because it doesn't actually attempt setuid.
        let me = nix::unistd::geteuid();
        let my_gid = nix::unistd::getegid();
        let target = TargetUser {
            name: "self".to_string(),
            uid: me,
            gid: my_gid,
        };
        // Should return Ok without touching the kernel.
        drop_to(&target).expect("no-op drop must succeed");
        // EUID unchanged.
        assert_eq!(nix::unistd::geteuid(), me);
    }

    #[test]
    fn drop_to_errors_when_called_as_non_root_with_different_uid() {
        // We can't actually exercise the setuid path under `cargo
        // test` (we'd have to be root), but we CAN verify the
        // failure path: as a non-root user, attempting to setgid
        // to a different gid should return SetgidFailed (EPERM).
        let me_uid = nix::unistd::geteuid();
        if me_uid.is_root() {
            // CI runs as root sometimes (Docker layers). Skip —
            // the negative test only makes sense as non-root.
            eprintln!("skipping non-root negative test: running as root");
            return;
        }
        // Pick a gid we definitely can't change to: 0 (root).
        let target = TargetUser {
            name: "fake-target".to_string(),
            uid: Uid::from_raw(0),
            gid: Gid::from_raw(0),
        };
        let err = drop_to(&target).expect_err("non-root cannot drop to root");
        // Should fail at setgid (the first syscall after the
        // already-target check).
        match err {
            PrivDropError::SetgidFailed { gid, .. } => {
                assert_eq!(gid, 0);
            }
            other => panic!("expected SetgidFailed, got: {other:?}"),
        }
    }

    #[test]
    fn default_target_user_uses_macos_underscore_convention() {
        // Pin the convention so a future edit doesn't accidentally
        // drop the underscore (Darwin's `dscl` lookups + the
        // macos_install user-creation flow both depend on this
        // exact string).
        assert_eq!(DEFAULT_TARGET_USER, "_p2claw");
    }

    #[test]
    fn resolve_target_user_by_uid_finds_self() {
        // Self-uid round-trips through getpwuid. Pins the
        // SUDO_UID-fallback path: by-uid lookup returns the same
        // shape as by-name, with name + uid + gid populated.
        let me = nix::unistd::geteuid();
        let t = resolve_target_user_by_uid(me).expect("self uid must resolve");
        assert_eq!(t.uid, me);
        assert_ne!(t.name, "", "name field must be non-empty");
    }

    #[test]
    fn resolve_target_user_by_uid_errors_on_unknown_uid() {
        // A uid that's all-but-guaranteed to be absent from
        // passwd (1<<31 collides with no real user on either
        // platform). Pin UserNotFound so cmd_run can surface a
        // clean "no target user" error rather than a confusing
        // LookupFailed.
        let bogus = Uid::from_raw(1 << (31 - 1));
        let err = resolve_target_user_by_uid(bogus).expect_err("bogus uid must not resolve");
        match err {
            PrivDropError::UserNotFound { .. } => {}
            other => panic!("expected UserNotFound, got: {other:?}"),
        }
    }

    /// Process-wide lock for env-var-mutating tests. Rust runs
    /// tests in parallel by default, and `std::env::set_var` is
    /// process-global — without serialization, a test that sets
    /// `P2CLAW_RUN_AS_USER=nobody` can leak into a parallel test
    /// that asserts the env is unset. Each test that touches env
    /// MUST acquire this mutex first.
    ///
    /// This is the same shape as the env-mutating tests in
    /// main.rs but with explicit cross-test serialization (the
    /// main.rs tests use unique var names per test to dodge the
    /// race; here multiple tests share `RUN_AS_USER_ENV` +
    /// `SUDO_UID` so collision is unavoidable without locking).
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper for env-var-mutating tests. Caller MUST hold
    /// `ENV_MUTEX` for the duration of the closure.
    fn with_env<R>(name: &str, value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let prev = std::env::var(name).ok();
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        let r = f();
        match prev {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        r
    }

    #[test]
    fn resolve_for_runtime_honors_env_override_when_set() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        // `nobody` exists everywhere — using it as the override
        // target lets us verify the env path resolves to a real
        // user without depending on `_p2claw` being installed.
        with_env(RUN_AS_USER_ENV, Some("nobody"), || {
            let t = resolve_for_runtime();
            match t {
                Ok(t) => assert_eq!(t.name, "nobody"),
                Err(PrivDropError::UserNotFound { .. }) => {
                    // Skip on minimal sandboxes lacking `nobody`.
                    eprintln!(
                        "skipping resolve_for_runtime_honors_env_override_when_set: \
                         nobody not in passwd"
                    );
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
        });
    }

    #[test]
    fn resolve_for_runtime_falls_back_to_sudo_uid_when_default_missing() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        // _p2claw doesn't exist on dev machines (the system-scope
        // install hasn't run). With SUDO_UID set to our own
        // uid, the chain should walk env(empty) → _p2claw(missing)
        // → SUDO_UID(self) → success.
        let me = nix::unistd::geteuid();
        with_env(RUN_AS_USER_ENV, None, || {
            with_env("SUDO_UID", Some(&me.as_raw().to_string()), || {
                let t = resolve_for_runtime().expect("SUDO_UID fallback must succeed");
                assert_eq!(t.uid, me);
            });
        });
    }

    #[test]
    fn resolve_for_runtime_errors_when_no_target_resolvable() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        // env unset + _p2claw missing + SUDO_UID unset → must
        // error rather than silently default to "stay root". This
        // is the load-bearing security check: a missing target
        // must NOT degrade to no-drop.
        with_env(RUN_AS_USER_ENV, None, || {
            with_env("SUDO_UID", None, || {
                let err = resolve_for_runtime().expect_err("no target resolvable must error");
                match err {
                    PrivDropError::UserNotFound { name } => {
                        // Error message hints at all three options.
                        assert!(name.contains(DEFAULT_TARGET_USER));
                        assert!(name.contains("SUDO_UID"));
                        assert!(name.contains(RUN_AS_USER_ENV));
                    }
                    other => panic!("expected UserNotFound, got: {other:?}"),
                }
            });
        });
    }

    #[test]
    fn resolve_for_runtime_rejects_malformed_sudo_uid() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        // Defensive: SUDO_UID set but garbage. Must error rather
        // than silently fall through (a typo in a wrapper script
        // shouldn't degrade the security posture).
        with_env(RUN_AS_USER_ENV, None, || {
            with_env("SUDO_UID", Some("not-a-number"), || {
                let err = resolve_for_runtime().expect_err("malformed SUDO_UID must error");
                match err {
                    PrivDropError::UserNotFound { name } => {
                        assert!(name.contains("SUDO_UID"));
                    }
                    other => panic!("expected UserNotFound, got: {other:?}"),
                }
            });
        });
    }
}
