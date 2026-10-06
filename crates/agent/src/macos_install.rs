//! macOS system-scope install integration.
//!
//! Today's `service` module installs the agent as a **user-scope
//! LaunchAgent** (`~/Library/LaunchAgents/dev.p2claw.agent.plist`),
//! which fits the per-user `p2claw run` daemon model and works
//! without `sudo`. That's the right shape for the agent's TCP
//! local-API socket + the user-scope identity files.
//!
//! The MagicDNS pipeline needs three things the
//! user-scope shape can't provide:
//!
//! 1. **Bind 443** — the local SNI listener (`sni_listener.rs`)
//!    accepts TLS on `127.0.0.1:443`. Ports < 1024 require root on
//!    macOS unless launchd holds the socket via the `Sockets` key
//!    (which we'd have to wire through the agent code as a
//!    socket-activation pickup). Simpler: run the agent under a
//!    **system-scope LaunchDaemon** as root.
//! 2. **System DNS resolver hook** — `/etc/resolver/<parent_domain>`
//!    is root-owned. macOS reads it on startup + on `mDNSResponder`
//!    SIGHUP; presence + content directs all `*.<parent_domain>`
//!    queries to the agent's loopback DNS resolver.
//! 3. **System trust store** — leaf certs minted by `local_ca`
//!    chain off a per-installation Ed25519 root. For browsers + curl
//!    + system tools to trust them, the root must live in the
//!    System Keychain (`/Library/Keychains/System.keychain`) with
//!    the SSL trust setting on. `security add-trusted-cert` is
//!    root-only.
//!
//! All three land at install time and reverse at uninstall.
//!
//! ## Failure modes the install code anticipates
//!
//! - **Not running as root.** The install command refuses to write
//!   the LaunchDaemon plist, the resolver file, or the keychain
//!   entry without uid 0. Operator re-runs with `sudo`.
//! - **Port 443 already bound.** The local SNI listener can't
//!   coexist with another HTTPS server on the same loopback. We
//!   pre-flight by attempting an immediate bind on
//!   `127.0.0.1:443`; if it fails with `EADDRINUSE`, the install
//!   aborts with a message naming the conflicting service (best-
//!   effort via `lsof`).
//! - **Stale install.** A previous LaunchDaemon still loaded gets
//!   `bootout`'d before the fresh install; same for the keychain
//!   entry (best-effort delete on the prior CN).
//! - **Missing CA root.** `local_ca::load_or_generate` writes the
//!   root cert to `<data_dir>/local_ca.crt`. If absent at install
//!   time, we run `local_ca::load_or_generate` ourselves to mint
//!   one — keeps install single-shot rather than requiring a prior
//!   `p2claw run` to seed the file.
//! - **Missing parent_domain.** The resolver file is keyed off the
//!   parent_domain coord assigned at registration. Read from the
//!   on-disk `agent.state` if present; fall back to an explicit
//!   `--parent-domain` flag for first-time installs that haven't
//!   registered yet.

#![cfg(target_os = "macos")]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::{info, warn};

/// LaunchDaemon label. Same shape as the LaunchAgent's, so an
/// operator who's used to `launchctl print system/dev.p2claw.agent`
/// already knows the namespacing.
pub const LAUNCHDAEMON_LABEL: &str = "dev.p2claw.agent";

/// LaunchDaemon plist filename, written under
/// `/Library/LaunchDaemons/`. The path is fixed by macOS — launchd
/// reads from this directory at boot + on
/// `launchctl bootstrap system <path>`.
pub const LAUNCHDAEMON_FILENAME: &str = "dev.p2claw.agent.plist";

/// Path under `/etc/resolver/` macOS reads. The filename is the
/// parent domain itself (no extension) — `man resolver` for the
/// full spec.
pub const ETC_RESOLVER_DIR: &str = "/etc/resolver";

/// Loopback DNS port the agent's `dns_resolver` module listens on.
/// Re-export of `dns_resolver::DEFAULT_BIND_PORT` so the
/// `/etc/resolver/<parent_domain>` file we write points at exactly
/// the port the resolver binds. Same bug-class as the Linux side
/// (a divergent local constant here would break every MagicDNS
/// query the same way it did under linux_install before the
/// fix).
pub const DNS_RESOLVER_PORT: u16 = p2claw_agent::dns_resolver::DEFAULT_BIND_PORT;

/// Common Name on the local CA root cert (set in
/// `local_ca::load_or_generate`). Used by uninstall to find +
/// remove the keychain entry. If `local_ca` ever changes its CN,
/// update this constant in lockstep.
pub const CA_ROOT_CN: &str = "p2claw local CA";

/// Where the system keychain lives. macOS-fixed.
pub const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("macOS system-scope install requires root; re-run with `sudo`")]
    NotRoot,
    #[error("port 443 is already bound on 0.0.0.0 or 127.0.0.1: {detail}")]
    PortConflict { detail: String },
    #[error("could not determine the running binary's path: {0}")]
    NoCurrentExe(#[source] std::io::Error),
    #[error("`{bin}` is not present at `{path}`")]
    BinNotFound { bin: &'static str, path: String },
    // `read_parent_domain_from_state` falls back to
    // `crate::DEFAULT_PARENT_DOMAIN` (canonical `p2claw.com`,
    // build-time overridable via `P2CLAW_DEFAULT_PARENT_DOMAIN`)
    // when neither the CLI flag nor `agent.state` provides one.
    // Fresh boxes that haven't yet registered don't see an
    // install-time nag.
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{tool} {action}` exited with status {status}: {stderr}")]
    ToolFailed {
        tool: &'static str,
        action: &'static str,
        status: String,
        stderr: String,
    },
    #[error("could not load/generate local CA root: {0}")]
    LocalCa(String),
}

/// Options for [`install_system`]. Each field has a sensible
/// default; CLI surface lets operators override.
pub struct InstallSystemOpts {
    /// Absolute path of the binary the LaunchDaemon should run.
    /// Defaults to [`std::env::current_exe`].
    pub bin_path: Option<PathBuf>,
    /// Parent domain coord assigned at registration (e.g.
    /// `p2claw.com`). Drives the resolver-file name. If `None`,
    /// read from `<data_dir>/agent.state`; if that's absent too,
    /// install fails with `NoParentDomain`.
    pub parent_domain: Option<String>,
    /// Where the agent stores `identity.key`, `agent.state`, and
    /// `local_ca.crt`. Defaults to the standard macOS path
    /// (`~/Library/Application Support/p2claw`); operators with
    /// non-default install layouts can override.
    pub data_dir: Option<PathBuf>,
    /// Skip the `launchctl bootstrap system` step. Useful for
    /// staging — write all the files but don't load the daemon.
    pub no_start: bool,
    /// Print every action without running it. Operators can dry-
    /// run an install before committing to the system-state
    /// changes.
    pub dry_run: bool,
}

/// Options for [`uninstall_system`]. Symmetric subset of install.
pub struct UninstallSystemOpts {
    /// Parent domain whose `/etc/resolver/<domain>` file we'll
    /// remove. If `None`, read from `<data_dir>/agent.state`.
    pub parent_domain: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub dry_run: bool,
}

/// Run the macOS system-scope install. See module docs.
pub fn install_system(opts: InstallSystemOpts) -> Result<(), InstallError> {
    if !is_root() && !opts.dry_run {
        return Err(InstallError::NotRoot);
    }

    // 1. Resolve the binary path the daemon should run.
    let bin = resolve_bin(opts.bin_path.clone())?;
    if !bin.exists() {
        return Err(InstallError::BinNotFound {
            bin: "p2claw",
            path: bin.display().to_string(),
        });
    }

    // 2. Resolve data_dir + parent_domain (fall back to agent.state
    //    if either is missing). Failure on parent_domain only — a
    //    fresh install with no agent.state can still proceed if
    //    --parent-domain is passed.
    let data_dir = opts.data_dir.clone().unwrap_or_else(default_macos_data_dir);
    let parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 3. Pre-flight: 443 isn't already bound elsewhere.
    if let Err(detail) = check_443_free() {
        return Err(InstallError::PortConflict { detail });
    }

    // 4. Make sure the CA root cert exists on disk; mint if
    //    missing. `local_ca::load_or_generate` is idempotent —
    //    re-reads on subsequent calls. Running here keeps install
    //    single-shot rather than requiring a prior `p2claw run`
    //    to seed the file.
    let ca_cert_path = data_dir.join("local_ca.crt");
    if !ca_cert_path.exists() {
        info!(
            data_dir = %data_dir.display(),
            "macos_install: minting local CA root (load_or_generate)"
        );
        if !opts.dry_run {
            std::fs::create_dir_all(&data_dir).map_err(|e| InstallError::Io {
                path: data_dir.display().to_string(),
                source: e,
            })?;
            p2claw_agent::local_ca::LocalCa::load_or_generate(&data_dir)
                .map_err(|e| InstallError::LocalCa(e.to_string()))?;
        }
    }

    // 5. Write /etc/resolver/<parent_domain>. macOS picks it up
    //    on next mDNSResponder reload (we trigger that ourselves
    //    via SIGHUP after install).
    let resolver_path = etc_resolver_path(&parent_domain);
    let resolver_body = render_resolver_file(DNS_RESOLVER_PORT);
    write_atomic(&resolver_path, &resolver_body, 0o644, opts.dry_run)?;
    print_action(opts.dry_run, &format!("wrote {}", resolver_path.display()));

    // 5b. Write `/etc/resolver/<coord_domain>` if we know
    //     coord_domain. This is the MagicDNS redirect-loop fix —
    //     macOS's longest-match-wins rule means coord-discovery
    //     queries hit this file first and route to public DNS,
    //     bypassing our local resolver entirely. See
    //     `render_coord_bypass_resolver_file` doc-comment.
    //
    //     We don't fail install if coord_domain is missing from
    //     agent.state — a fresh install before registration just
    //     gets the parent-domain file; the bypass becomes redundant
    //     if no peer-dialer ever runs without registration anyway.
    if let Some(coord_domain) = read_coord_domain_from_state(&data_dir) {
        let coord_resolver_path = etc_resolver_path(&coord_domain);
        let coord_resolver_body = render_coord_bypass_resolver_file();
        write_atomic(
            &coord_resolver_path,
            &coord_resolver_body,
            0o644,
            opts.dry_run,
        )?;
        print_action(
            opts.dry_run,
            &format!(
                "wrote {} (coord-bypass; routes coord queries to public DNS)",
                coord_resolver_path.display()
            ),
        );
    } else {
        print_action(
            opts.dry_run,
            "(no coord_domain in agent.state; skipped /etc/resolver/<coord> coord-bypass — \
             will be added on next install once registration completes)",
        );
    }

    // 6. Install CA root into the System Keychain. SSL trust is
    //    set via `-r trustRoot`; `security` will prompt the user
    //    (an admin TouchID / password sheet) on the first run.
    let ca_cert_path_str = ca_cert_path.display().to_string();
    let ca_install_args: [&str; 7] = [
        "add-trusted-cert",
        "-d",
        "-r",
        "trustRoot",
        "-k",
        SYSTEM_KEYCHAIN_PATH,
        &ca_cert_path_str,
    ];
    if !opts.dry_run {
        // macOS's SecurityAgent wants a GUI prompt
        // for trust-policy changes, even with sudo. SSH / no-Aqua
        // sessions can't display the prompt and the call fails
        // with status 125: `SecTrustSettingsSetTrustSettings: The
        // authorization was denied without an interaction was
        // possible.` Known-painful: Caddy local-mode + mkcert hit
        // it too. Don't blow up the whole install — the cert is
        // on disk + the LaunchDaemon plist gets written below.
        // Print clear manual instructions and proceed. Operator
        // can finish the trust-add step via Keychain Access.app
        // from their desktop.
        match run_tool("security", "add-trusted-cert", &ca_install_args) {
            Ok(()) => print_action(
                opts.dry_run,
                &format!(
                    "installed CA root into {SYSTEM_KEYCHAIN_PATH} \
                     (security add-trusted-cert -d -r trustRoot -k {SYSTEM_KEYCHAIN_PATH} {})",
                    ca_cert_path.display()
                ),
            ),
            Err(InstallError::ToolFailed { status, stderr, .. })
                if status.contains("125")
                    || stderr.contains("authorization was denied")
                    || stderr.contains("SecTrustSettings") =>
            {
                println!();
                println!("⚠ macOS refused to add the local CA to the System Keychain.");
                println!("  This usually means SecurityAgent needs a GUI prompt that");
                println!("  isn't available in your current session (SSH / non-desktop).");
                println!();
                println!("  The CA cert is at:");
                println!("    {}", ca_cert_path.display());
                println!();
                println!("  To finish trusting it, from your DESKTOP (not SSH):");
                println!("  1. Open Keychain Access.app");
                println!(
                    "  2. Drag {} into 'System' keychain",
                    ca_cert_path.display()
                );
                println!("  3. Double-click the cert → expand 'Trust' → set");
                println!("     'When using this certificate' to 'Always Trust'");
                println!("  4. Close the dialog (Touch ID / password prompt)");
                println!();
                println!("  Until then, browsers + curl on this machine will reject p2claw's");
                println!("  per-SNI leaf certs. The agent itself will still run.");
                println!();
                println!("  Continuing with install — DNS resolver + LaunchDaemon next.");
                println!();
            }
            Err(e) => return Err(e),
        }
    } else {
        print_action(
            opts.dry_run,
            &format!(
                "installed CA root into {SYSTEM_KEYCHAIN_PATH} \
                 (security add-trusted-cert -d -r trustRoot -k {SYSTEM_KEYCHAIN_PATH} {})",
                ca_cert_path.display()
            ),
        );
    }

    // 7. Render + write the LaunchDaemon plist.
    let log_path = launchdaemon_log_path();
    if let Some(parent) = log_path.parent() {
        if !opts.dry_run {
            std::fs::create_dir_all(parent).map_err(|e| InstallError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
    }
    // Cross-platform parity: same env-capture allow-list as
    // linux_install. Without this, `launchctl bootstrap`'s
    // freshly-spawned daemon has only the env declared in the
    // plist + launchd's PID 1 inherited env — NOT the install-
    // time shell's `P2CLAW_*` vars. Daemon falls through to clap
    // defaults (`coord_domain=coord.p2claw.com`), the same
    // bug-class that hit on Linux.
    let captured: Vec<(&str, Option<String>)> = vec![
        ("P2CLAW_COORD_URL", std::env::var("P2CLAW_COORD_URL").ok()),
        (
            "P2CLAW_COORD_DOMAIN",
            std::env::var("P2CLAW_COORD_DOMAIN").ok(),
        ),
        (
            crate::auto_upgrade::RELEASE_REPO_ENV,
            std::env::var(crate::auto_upgrade::RELEASE_REPO_ENV).ok(),
        ),
        // DNS-port override capture mirrors linux_install.
        // macOS's `/etc/resolver/<parent>` accepts a `port`
        // directive (unlike Windows NRPT), so operators who want a
        // non-5354 port (e.g., 53 with the agent running as root
        // post-priv-drop) can set the env at install time
        // and the value bakes into the LaunchDaemon plist.
        ("P2CLAW_DNS_PORT", std::env::var("P2CLAW_DNS_PORT").ok()),
    ];
    let extra_env: Vec<(&str, &str)> = captured
        .iter()
        .filter_map(|(k, v)| v.as_deref().map(|s| (*k, s)))
        .collect();
    let plist_body = render_launchdaemon_plist(&bin, &log_path, &extra_env);
    let plist_path = launchdaemon_plist_path();
    write_atomic(&plist_path, &plist_body, 0o644, opts.dry_run)?;
    print_action(opts.dry_run, &format!("wrote {}", plist_path.display()));
    if !extra_env.is_empty() {
        let keys = extra_env
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(", ");
        print_action(
            opts.dry_run,
            &format!("(captured install-time env into plist EnvironmentVariables: {keys})"),
        );
    }

    // 8. Load the daemon (unless --no-start). Symmetric to
    //    user-scope install: bootout any prior instance first
    //    (best-effort), then bootstrap fresh.
    if opts.no_start {
        print_action(
            opts.dry_run,
            &format!(
                "(--no-start) skipped `launchctl bootstrap system`. Load later with:\n  \
                 sudo launchctl bootstrap system {}",
                plist_path.display()
            ),
        );
    } else if !opts.dry_run {
        let target = format!("system/{LAUNCHDAEMON_LABEL}");
        let _ = run_tool(
            "launchctl",
            "bootout (best-effort)",
            &["bootout".to_string(), target.clone()]
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        );
        run_tool(
            "launchctl",
            "bootstrap system",
            &["bootstrap", "system", plist_path.to_str().unwrap_or("")],
        )?;
        let _ = run_tool("launchctl", "enable", &["enable", &target]);
        print_action(
            opts.dry_run,
            &format!("loaded {LAUNCHDAEMON_LABEL} via launchctl"),
        );
    }

    // 9. Ask mDNSResponder to re-read /etc/resolver/. Best-effort:
    //    on a fresh boot it picks up automatically; on an in-
    //    place install we want resolution to start working
    //    immediately.
    if !opts.dry_run {
        let _ = run_tool("dscacheutil", "flushcache", &["-flushcache"]);
        let _ = run_tool("killall", "-HUP mDNSResponder", &["-HUP", "mDNSResponder"]);
    }

    print_action(opts.dry_run, "macos_install: done");
    Ok(())
}

/// Reverse of [`install_system`]. Best-effort on each step — a
/// missing file isn't a failure, it just means a partial prior
/// uninstall already cleaned that piece: we report what we did
/// and don't refuse to continue if a piece is already gone.
pub fn uninstall_system(opts: UninstallSystemOpts) -> Result<(), InstallError> {
    if !is_root() && !opts.dry_run {
        return Err(InstallError::NotRoot);
    }

    let data_dir = opts.data_dir.clone().unwrap_or_else(default_macos_data_dir);
    // parent_domain resolves via the same chain as install
    // (flag → state file → compile-time default), so uninstall always
    // has a domain to point at. The resolver-file removal is gated
    // on `resolver_path.exists()` below — if the install used a
    // different domain than the default, the missing-file branch
    // just prints "(no resolver at ...)" and continues.
    let parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 1. Bootout the LaunchDaemon (best-effort).
    if !opts.dry_run {
        let target = format!("system/{LAUNCHDAEMON_LABEL}");
        if let Err(e) = run_tool("launchctl", "bootout", &["bootout", &target]) {
            warn!(error = %e, "macos_install: launchctl bootout (uninstall) failed");
        }
    }

    // 2. Remove the plist file.
    let plist_path = launchdaemon_plist_path();
    if plist_path.exists() {
        if !opts.dry_run {
            std::fs::remove_file(&plist_path).map_err(|e| InstallError::Io {
                path: plist_path.display().to_string(),
                source: e,
            })?;
        }
        print_action(opts.dry_run, &format!("removed {}", plist_path.display()));
    } else {
        print_action(
            opts.dry_run,
            &format!("(no plist at {})", plist_path.display()),
        );
    }

    // 3. Remove the resolver file. `parent_domain` is always set
    //    (falls back to compile-time default); the
    //    `resolver_path.exists()` gate keeps this safe when the
    //    real install used a different domain.
    {
        let resolver_path = etc_resolver_path(&parent_domain);
        if resolver_path.exists() {
            if !opts.dry_run {
                std::fs::remove_file(&resolver_path).map_err(|e| InstallError::Io {
                    path: resolver_path.display().to_string(),
                    source: e,
                })?;
            }
            print_action(
                opts.dry_run,
                &format!("removed {}", resolver_path.display()),
            );
        } else {
            print_action(
                opts.dry_run,
                &format!("(no resolver at {})", resolver_path.display()),
            );
        }
    }

    // 3b. Remove the coord-bypass resolver file too. We
    //     read coord_domain from agent.state — same caveat as
    //     install: if it's missing the file was never written.
    if let Some(coord_domain) = read_coord_domain_from_state(&data_dir) {
        let coord_resolver_path = etc_resolver_path(&coord_domain);
        if coord_resolver_path.exists() {
            if !opts.dry_run {
                std::fs::remove_file(&coord_resolver_path).map_err(|e| InstallError::Io {
                    path: coord_resolver_path.display().to_string(),
                    source: e,
                })?;
            }
            print_action(
                opts.dry_run,
                &format!("removed {} (coord-bypass)", coord_resolver_path.display()),
            );
        } else {
            print_action(
                opts.dry_run,
                &format!(
                    "(no coord-bypass resolver at {})",
                    coord_resolver_path.display()
                ),
            );
        }
    } else {
        print_action(
            opts.dry_run,
            "(no coord_domain in agent.state; skipped /etc/resolver/<coord> removal)",
        );
    }

    // 4. Remove the CA root from the system keychain.
    //    `security delete-certificate -c <cn>` removes by Common
    //    Name. Best-effort — if the cert isn't present we don't
    //    treat that as a failure.
    if !opts.dry_run {
        let _ = run_tool(
            "security",
            "delete-certificate",
            &["delete-certificate", "-c", CA_ROOT_CN, SYSTEM_KEYCHAIN_PATH],
        );
    }
    print_action(
        opts.dry_run,
        &format!("removed CA root '{CA_ROOT_CN}' from {SYSTEM_KEYCHAIN_PATH} (best-effort)"),
    );

    // 5. Flush DNS cache so resolver changes take effect.
    if !opts.dry_run {
        let _ = run_tool("dscacheutil", "flushcache", &["-flushcache"]);
        let _ = run_tool("killall", "-HUP mDNSResponder", &["-HUP", "mDNSResponder"]);
    }

    print_action(opts.dry_run, "macos_install: uninstall done");
    Ok(())
}

/// Pre-flight check used by [`install_system`]: refuses install if
/// 0.0.0.0:443 or 127.0.0.1:443 is already bound. Avoids the
/// post-install surprise of "the LaunchDaemon loaded but the SNI
/// listener can't bind."
///
/// Best-effort detection of WHO owns the port via `lsof -i :443`
/// — if `lsof` isn't available or fails, we still surface the
/// EADDRINUSE error without the helpful name.
pub fn check_443_free() -> Result<(), String> {
    // Try binding 127.0.0.1:443 with SO_REUSEADDR off (default).
    // EADDRINUSE means someone else owns it.
    match TcpListener::bind("127.0.0.1:443") {
        Ok(l) => {
            drop(l);
        }
        Err(e) => {
            // Try to attribute via lsof — informational only.
            let detail = match Command::new("lsof").args(["-i", ":443"]).output() {
                Ok(out) if out.status.success() => format!(
                    "127.0.0.1:443 bind failed ({e}); current owner per `lsof -i :443`:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                ),
                _ => format!("127.0.0.1:443 bind failed ({e}); install `lsof` for owner info"),
            };
            return Err(detail);
        }
    }
    // Also probe 0.0.0.0:443 — a server bound to all-interfaces
    // would show up as a 127.0.0.1 conflict above too, but a
    // belt-and-suspenders check on both addresses catches edge
    // cases where the OS routes loopback differently from
    // wildcards.
    match TcpListener::bind("0.0.0.0:443") {
        Ok(l) => {
            drop(l);
        }
        Err(e) => {
            return Err(format!("0.0.0.0:443 bind failed ({e})"));
        }
    }
    Ok(())
}

/// macOS-shape `/etc/resolver/<parent_domain>` body. Per `man 5
/// resolver`: bare `nameserver` line + `port` line points all
/// `*.<parent_domain>` queries at the local DNS resolver.
pub fn render_resolver_file(loopback_port: u16) -> String {
    format!(
        "# Generated by `p2claw service install --system`. Reverses on uninstall.\n\
         # Routes *.<parent_domain> queries to the local p2claw DNS resolver\n\
         # (`crates/agent/src/dns_resolver.rs`) which synthesizes A records\n\
         # at 127.0.0.1 + chains everything else upstream. See `man 5 resolver`.\n\
         nameserver 127.0.0.1\n\
         port {loopback_port}\n",
    )
}

/// Public DNS upstreams for the coord-bypass resolver file.
/// Cloudflare's 1.1.1.1 + Google's 8.8.8.8 — both reachable from
/// every public network we care about. Pinned here rather than
/// snapshotting `/etc/resolv.conf` at install time because resolv
/// upstreams change as the machine roams (DHCP renewal, VPN
/// up/down, etc.) — a snapshot would go stale. Public resolvers
/// are stable.
///
/// Operators on private networks where these aren't reachable can
/// override by editing `/etc/resolver/<coord_domain>` after install.
pub const COORD_BYPASS_UPSTREAMS: &[&str] = &["1.1.1.1", "8.8.8.8"];

/// Render `/etc/resolver/<coord_domain>` body. Routes coord-discovery
/// DNS queries from THIS box around our local resolver — direct to
/// public upstreams. Mirrors the `Domains=~` semantics on Linux's
/// systemd-resolved drop-in (which routes `~p2claw.com` to our
/// resolver but lets coord-subdomain bypass via the resolver's
/// `reserved_subdomains` list).
///
/// The MagicDNS redirect-loop fix: without this file, a
/// coord-discovery DNS query from the agent's own peer-dialer
/// would route through `/etc/resolver/<parent_domain>` → our
/// resolver → reserved-subdomain bypass → forward upstream. The
/// "forward upstream" step pulls upstreams from
/// `/etc/resolv.conf`, which on macOS may be empty / minimal /
/// loopback-pointing depending on network state — and even when
/// it has real upstreams, the system-resolver chain on the
/// outbound side may re-apply the `/etc/resolver/<parent>`
/// hijack, looping back through us. Writing this file with a
/// longer (more specific) name makes macOS's longest-match-wins
/// rule short-circuit the loop entirely: coord queries skip our
/// resolver from the start, hit public DNS directly, get a real
/// IP, return.
pub fn render_coord_bypass_resolver_file() -> String {
    let mut body = String::new();
    body.push_str(
        "# Generated by `p2claw service install --system`. Reverses on uninstall.\n\
         # Coord-bypass for the MagicDNS redirect loop. macOS resolver-dir\n\
         # uses longest-match-wins per `man 5 resolver`, so this file\n\
         # (`/etc/resolver/<coord_domain>`) takes precedence over the more-general\n\
         # `/etc/resolver/<parent_domain>` for queries to coord's own hostname.\n\
         # Routes coord-discovery DNS straight to public upstreams; never touches\n\
         # our local resolver — eliminates the chance of a loop regardless of\n\
         # what `/etc/resolv.conf` contains at runtime.\n",
    );
    for ns in COORD_BYPASS_UPSTREAMS {
        body.push_str(&format!("nameserver {ns}\n"));
    }
    body
}

/// Render the LaunchDaemon plist. Runs the agent as root (no
/// `UserName` key) so it can bind 443; the agent process drops
/// privileges to a non-root target user immediately after binding
/// (`priv_drop::drop_to`, called from `main.rs::cmd_run` once the
/// privileged sockets are open).
pub fn render_launchdaemon_plist(
    bin_path: &Path,
    log_path: &Path,
    extra_env: &[(&str, &str)],
) -> String {
    // Render any operator-supplied env captures (currently
    // `P2CLAW_COORD_URL` / `P2CLAW_COORD_DOMAIN` /
    // `P2CLAW_RELEASE_REPO` / etc) as additional
    // `<key>NAME</key><string>VALUE</string>` entries inside
    // `<key>EnvironmentVariables</key><dict>...</dict>`. Cross-
    // platform parity with linux_install's `Environment=` lines
    // Same bug-class on launchd: the daemon's env at
    // run-time is whatever the plist declares — not what was
    // present in the install-time shell. Without these captures,
    // any operator-set `P2CLAW_*` env from the install shell is
    // lost when launchd later starts the daemon, daemon falls
    // through to clap defaults.
    let extra_env_lines = extra_env
        .iter()
        .map(|(k, v)| {
            // Indent to match the existing PATH line's 8-space
            // leading whitespace inside the EnvironmentVariables
            // <dict>. plist parsers don't care about indent, but
            // a future operator reading the file does.
            format!("        <key>{k}</key>\n        <string>{v}</string>")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let extra_env_block = if extra_env_lines.is_empty() {
        String::new()
    } else {
        format!("\n{extra_env_lines}")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>{extra_env_block}
    </dict>
</dict>
</plist>
"#,
        label = LAUNCHDAEMON_LABEL,
        bin = bin_path.display(),
        log = log_path.display(),
        extra_env_block = extra_env_block,
    )
}

// ---------- helpers ----------

fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

fn launchdaemon_plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(LAUNCHDAEMON_FILENAME)
}

fn launchdaemon_log_path() -> PathBuf {
    PathBuf::from("/Library/Logs/p2claw/p2claw.log")
}

fn etc_resolver_path(parent_domain: &str) -> PathBuf {
    PathBuf::from(ETC_RESOLVER_DIR).join(parent_domain)
}

fn default_macos_data_dir() -> PathBuf {
    // Mirrors `crate::config::data_dir()` for macOS — kept inline
    // so this module doesn't need to depend on the bin's `config`
    // module (which is `mod config;` in main.rs and not part of
    // the lib facet).
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/p2claw")
}

fn resolve_bin(override_: Option<PathBuf>) -> Result<PathBuf, InstallError> {
    let p = match override_ {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoCurrentExe)?,
    };
    Ok(p.canonicalize().unwrap_or(p))
}

/// Resolve the parent domain to use for install operations,
/// falling back to the compile-time default when neither
/// the CLI flag (caller checks first) nor `agent.state` provides
/// one. Order on disk: state-file value → `crate::DEFAULT_PARENT_DOMAIN`.
///
/// Never errors — fresh boxes that haven't yet registered get
/// the canonical `p2claw.com` (or the build-time
/// `P2CLAW_DEFAULT_PARENT_DOMAIN` override) and `--system`
/// install proceeds without nagging for `--parent-domain`.
fn read_parent_domain_from_state(data_dir: &Path) -> String {
    let state_path = data_dir.join("agent.state");
    // Cheap parse: agent.state is JSON; pull `parent_domain` out
    // without dragging in the full state_store types (which would
    // pull p2claw_identity::PeerId etc.).
    let parsed = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|v| {
            v.get("parent_domain")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        });
    parsed.unwrap_or_else(|| crate::DEFAULT_PARENT_DOMAIN.to_string())
}

/// Sibling of [`read_parent_domain_from_state`] — pulls
/// `coord_domain` (e.g. `coord.p2claw.com`) instead. Used by the
/// MagicDNS-redirect-loop fix: we install a more-specific
/// `/etc/resolver/<coord_domain>` that points at public upstream
/// nameservers, so coord-discovery DNS queries from THIS box
/// bypass our resolver entirely. macOS resolver-dir uses
/// longest-match-wins per `man 5 resolver`, so the coord file
/// takes precedence over the more-general
/// `/etc/resolver/<parent_domain>` for `coord.<parent>` queries.
///
/// Returns `Ok(None)` if `agent.state` has no `coord_domain`
/// field (legacy state file — the dial site
/// would already refuse to operate against an absent
/// `coord_root_pubkey`, so silently skipping the bypass write is
/// the right shape: nothing to bypass anyway).
fn read_coord_domain_from_state(data_dir: &Path) -> Option<String> {
    let state_path = data_dir.join("agent.state");
    let bytes = std::fs::read(&state_path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("coord_domain")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

fn write_atomic(path: &Path, contents: &str, mode: u32, dry_run: bool) -> Result<(), InstallError> {
    if dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp_path)
        .map_err(|e| InstallError::Io {
            path: tmp_path.display().to_string(),
            source: e,
        })?;
    f.write_all(contents.as_bytes())
        .map_err(|e| InstallError::Io {
            path: tmp_path.display().to_string(),
            source: e,
        })?;
    f.sync_all().map_err(|e| InstallError::Io {
        path: tmp_path.display().to_string(),
        source: e,
    })?;
    drop(f);
    std::fs::rename(&tmp_path, path).map_err(|e| InstallError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn run_tool(tool: &'static str, action: &'static str, args: &[&str]) -> Result<(), InstallError> {
    let out = Command::new(tool)
        .args(args)
        .output()
        .map_err(|e| InstallError::ToolFailed {
            tool,
            action,
            status: format!("spawn failed: {e}"),
            stderr: String::new(),
        })?;
    if !out.status.success() {
        return Err(InstallError::ToolFailed {
            tool,
            action,
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

fn print_action(dry_run: bool, line: &str) {
    if dry_run {
        println!("(dry-run) {line}");
    } else {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_file_render_includes_loopback_and_port() {
        let body = render_resolver_file(5454);
        assert!(body.contains("nameserver 127.0.0.1"));
        assert!(body.contains("port 5454"));
        // Header comment must reference uninstall reversibility so an
        // operator who finds the file can grep the codebase.
        assert!(body.contains("Reverses on uninstall"));
    }

    /// Coord-bypass file MUST point at public DNS, NOT
    /// loopback. macOS's longest-match-wins resolver-dir routing
    /// means coord queries hit this file first; if it pointed at
    /// 127.0.0.1 we'd be back to the redirect loop. Pin the public
    /// upstreams + the no-loopback property so a future edit can't
    /// reintroduce the bug.
    #[test]
    fn coord_bypass_resolver_render_uses_public_upstreams_not_loopback() {
        let body = render_coord_bypass_resolver_file();
        // Both public upstreams listed.
        assert!(body.contains("nameserver 1.1.1.1"));
        assert!(body.contains("nameserver 8.8.8.8"));
        // Loopback explicitly absent — would re-introduce the loop.
        assert!(
            !body.contains("nameserver 127."),
            "coord-bypass file must not list loopback as upstream:\n{body}"
        );
        assert!(
            !body.contains("port "),
            "coord-bypass uses default port 53; no `port` directive should appear:\n{body}"
        );
        assert!(body.contains("Reverses on uninstall"));
    }

    #[test]
    fn coord_bypass_upstreams_constant_is_stable() {
        // Pin the constant — operator overrides should be done by
        // editing the rendered file post-install, not by changing
        // the binary's defaults silently. Test fires on any change
        // so the release notes can call out the upstream choice.
        assert_eq!(
            COORD_BYPASS_UPSTREAMS,
            &["1.1.1.1", "8.8.8.8"],
            "Cloudflare + Google chosen for portability across public networks"
        );
    }

    #[test]
    fn read_coord_domain_from_state_extracts_field() {
        let dir = tempfile::tempdir().unwrap();
        let state = serde_json::json!({
            "alias": "test-alias-1234",
            "coord_domain": "coord.p2claw.com",
            "parent_domain": "p2claw.com",
            "coord_root_pubkey_b64url": "AAAA",
        });
        std::fs::write(
            dir.path().join("agent.state"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        let got = read_coord_domain_from_state(dir.path());
        assert_eq!(got.as_deref(), Some("coord.p2claw.com"));
    }

    #[test]
    fn read_coord_domain_from_state_returns_none_when_missing() {
        // Legacy agent.state with no coord_domain field — install
        // must skip the bypass write rather than fail. Different
        // from `read_parent_domain_from_state` (which was made
        // infallible by falling back to the compile-time default);
        // `coord_domain` has no analogous default — if we don't
        // know it, we can't know which suffix to bypass, so skip.
        let dir = tempfile::tempdir().unwrap();
        let state = serde_json::json!({
            "alias": "test",
            "parent_domain": "p2claw.com",
        });
        std::fs::write(
            dir.path().join("agent.state"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert!(read_coord_domain_from_state(dir.path()).is_none());
    }

    #[test]
    fn read_coord_domain_from_state_returns_none_when_state_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No agent.state file at all.
        assert!(read_coord_domain_from_state(dir.path()).is_none());
    }

    #[test]
    fn launchdaemon_plist_render_emits_extra_env_entries() {
        // Cross-platform parity for the env-capture fix.
        // Without these EnvironmentVariables entries,
        // any `P2CLAW_*` env that was set in the install-time
        // shell is lost when launchd starts the daemon — daemon
        // falls through to clap defaults, exact same bug class
        // we just fixed on Linux. Pin the serialization shape so
        // a future template edit doesn't accidentally drop the
        // entries.
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let log = PathBuf::from("/Library/Logs/p2claw/p2claw.log");
        let extra = [
            ("P2CLAW_COORD_URL", "http://coord:8081"),
            ("P2CLAW_COORD_DOMAIN", "coord.p2claw.test"),
        ];
        let plist = render_launchdaemon_plist(&bin, &log, &extra);
        assert!(
            plist.contains("<key>P2CLAW_COORD_URL</key>")
                && plist.contains("<string>http://coord:8081</string>"),
            "missing captured P2CLAW_COORD_URL plist entry; got:\n{plist}"
        );
        assert!(
            plist.contains("<key>P2CLAW_COORD_DOMAIN</key>")
                && plist.contains("<string>coord.p2claw.test</string>"),
            "missing captured P2CLAW_COORD_DOMAIN plist entry"
        );
        // Always-emitted PATH still present alongside.
        assert!(plist.contains("<key>PATH</key>"));
    }

    #[test]
    fn launchdaemon_plist_render_with_no_extra_env_omits_extra_block() {
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let log = PathBuf::from("/Library/Logs/p2claw/p2claw.log");
        let plist = render_launchdaemon_plist(&bin, &log, &[]);
        // Only the always-emitted PATH key inside
        // EnvironmentVariables. No P2CLAW_* keys leaked in.
        assert!(plist.contains("<key>PATH</key>"));
        assert!(
            !plist.contains("<key>P2CLAW_"),
            "empty extra_env should not emit any P2CLAW_* entries; got:\n{plist}"
        );
    }

    #[test]
    fn launchdaemon_plist_render_embeds_bin_path_and_label() {
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let log = PathBuf::from("/Library/Logs/p2claw/p2claw.log");
        let plist = render_launchdaemon_plist(&bin, &log, &[]);
        assert!(plist.contains("<string>/opt/p2claw/p2claw</string>"));
        assert!(plist.contains(&format!("<string>{LAUNCHDAEMON_LABEL}</string>")));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        // Inherits the FD-limit bump from the user-scope LaunchAgent
        // (FD-limit fix); operator-shipped fixes shouldn't regress under
        // system-scope.
        assert!(plist.contains("NumberOfFiles"));
        assert!(plist.contains("65536"));
    }

    #[test]
    fn etc_resolver_path_uses_parent_domain_as_filename() {
        // /etc/resolver/<domain> is macOS-fixed shape per
        // `man 5 resolver`. Filename = the domain (no extension).
        let p = etc_resolver_path("p2claw.com");
        assert_eq!(p, PathBuf::from("/etc/resolver/p2claw.com"));
    }

    #[test]
    fn launchdaemon_plist_path_is_system_scope_macos_fixed() {
        let p = launchdaemon_plist_path();
        assert_eq!(
            p,
            PathBuf::from("/Library/LaunchDaemons/dev.p2claw.agent.plist")
        );
    }

    #[test]
    fn read_parent_domain_from_state_extracts_field() {
        let dir = tempfile::tempdir().unwrap();
        // Minimal agent.state JSON shape (mirrors what
        // state_store::save writes; only `parent_domain` matters
        // for this test).
        let state = serde_json::json!({
            "alias": "test-alias-1234",
            "coord_domain": "coord.p2claw.com",
            "parent_domain": "registered.example",
            "coord_root_pubkey_b64url": "AAAA",
        });
        std::fs::write(
            dir.path().join("agent.state"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        // State-file value beats the compile-time default — the
        // box has registered to a custom parent_domain that wins
        // over `crate::DEFAULT_PARENT_DOMAIN`.
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            "registered.example"
        );
    }

    /// A fresh box that hasn't yet registered (no
    /// `agent.state`) gets the compile-time default instead of an
    /// install-time error nagging the operator for
    /// `--parent-domain`. With `P2CLAW_DEFAULT_PARENT_DOMAIN`
    /// unset, that default is `p2claw.com`.
    #[test]
    fn read_parent_domain_from_state_falls_back_to_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            crate::DEFAULT_PARENT_DOMAIN
        );
    }

    #[test]
    fn read_parent_domain_from_state_falls_back_to_default_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("agent.state"), b"this is not json").unwrap();
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            crate::DEFAULT_PARENT_DOMAIN
        );
    }

    #[test]
    fn read_parent_domain_from_state_falls_back_to_default_when_field_missing() {
        // JSON parses but no `parent_domain` field — fall back to
        // the compile-time default rather than erroring.
        let dir = tempfile::tempdir().unwrap();
        let state = serde_json::json!({ "alias": "test" });
        std::fs::write(
            dir.path().join("agent.state"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            crate::DEFAULT_PARENT_DOMAIN
        );
    }
}
