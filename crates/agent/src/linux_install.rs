//! Linux system-scope install integration.
//!
//! Mirror of `macos_install` for Linux. Today's `service`
//! module installs the agent as a **user-scope `systemd --user`
//! unit** (`~/.config/systemd/user/p2claw-agent.service`) which
//! works without `sudo` and fits the per-user `p2claw run` daemon
//! shape. That's the right layer for the local-API socket + the
//! per-user identity files.
//!
//! The MagicDNS pipeline needs three things the
//! user-scope shape can't provide:
//!
//! 1. **Bind 443** — the local SNI listener accepts TLS on
//!    `127.0.0.1:443`. Ports < 1024 require `CAP_NET_BIND_SERVICE`
//!    on Linux. We grant it via `AmbientCapabilities=CAP_NET_BIND_SERVICE`
//!    on the systemd unit, run with `User=` set to a less-
//!    privileged target (or root if no target user is configured;
//!    same hazard as the macOS path). The
//!    capability scope means we don't need a manual `setuid`
//!    drop in agent code — kernel grants the capability per-process,
//!    not for-life-of-binary.
//! 2. **System DNS resolver hook** — Linux is fragmented here
//!    (systemd-resolved / NetworkManager / dnsmasq / plain
//!    resolv.conf); we target **systemd-resolved** since it's
//!    the modern default on Debian/Ubuntu/Fedora and works
//!    cleanly via the `Domains=` directive (route specific
//!    domains to a specific DNS server). Drop a config snippet
//!    into `/etc/systemd/resolved.conf.d/p2claw.conf` + restart
//!    `systemd-resolved` on install.
//! 3. **System trust store** — leaf certs minted by `local_ca`
//!    chain off a per-installation Ed25519 root. For browsers, curl,
//!    and system tools to trust them, the root must live in the
//!    distro CA bundle. Debian/Ubuntu: copy to
//!    `/usr/local/share/ca-certificates/p2claw-local-ca.crt` +
//!    run `update-ca-certificates`. Fedora/RHEL: different path
//!    (`/etc/pki/ca-trust/source/anchors/`) + different command
//!    (`update-ca-trust`). We target the Debian path; we detect
//!    Fedora and surface a clear error directing the operator to
//!    run the appropriate command manually until distro
//!    detection lands.
//!
//! All three land at install time and reverse at uninstall.
//! Tests for the render functions live in this module
//! (compile + run on Linux only via `#![cfg]` gating, same as
//! `macos_install`).
//!
//! ## Comparison with macOS
//!
//! | concern             | macOS                                      | Linux                                                |
//! |---------------------|--------------------------------------------|------------------------------------------------------|
//! | service unit        | LaunchDaemon (system scope)                | systemd unit (system scope)                          |
//! | unit path           | /Library/LaunchDaemons/dev.p2claw.agent.plist | /etc/systemd/system/p2claw-agent.service           |
//! | bind-low-port      | run as root, then drop privileges          | `AmbientCapabilities=CAP_NET_BIND_SERVICE`         |
//! | DNS hook            | /etc/resolver/<parent_domain>              | /etc/systemd/resolved.conf.d/p2claw.conf             |
//! | DNS reload          | killall -HUP mDNSResponder                 | systemctl restart systemd-resolved                   |
//! | trust store install | security add-trusted-cert -k SystemKeychain | cp + update-ca-certificates                        |
//! | trust store remove  | security delete-certificate -c "<cn>"      | rm + update-ca-certificates                          |
//! | conflict pre-flight | TcpListener::bind 127.0.0.1:443 + 0.0.0.0:443 | same                                              |

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::{info, warn};

/// systemd unit filename. Same name as the user-scope unit so an
/// operator who's used to `systemctl --user status p2claw-agent`
/// can switch to `sudo systemctl status p2claw-agent` without
/// remembering a different label.
pub const SYSTEMD_UNIT_FILENAME: &str = "p2claw-agent.service";

/// Where system-scope systemd units live on Debian/Ubuntu/Fedora.
/// Distro-fixed.
pub const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";

/// Drop-in directory `systemd-resolved` reads on startup + on
/// `systemctl reload`. Per `man resolved.conf`.
pub const RESOLVED_DROPIN_DIR: &str = "/etc/systemd/resolved.conf.d";

/// Drop-in filename for our DNS routing snippet. systemd merges
/// any `*.conf` in the dropin dir; using a `p2claw.conf` keeps
/// uninstall's `rm` unambiguous.
pub const RESOLVED_DROPIN_FILENAME: &str = "p2claw.conf";

/// Loopback DNS port the agent's `dns_resolver` module listens on.
/// Re-export of `dns_resolver::DEFAULT_BIND_PORT` so the
/// systemd-resolved drop-in we render points at exactly the port
/// the resolver binds. A real bug-of-record was a local
/// `5454` constant here while the resolver bound `5354` —
/// systemd-resolved sent queries to a port nothing was listening
/// on, every box-A → box-B curl failed with `curl: (6)`. Single
/// source of truth lives in `dns_resolver`; this re-export is
/// purely a convenience so the render function reads naturally.
pub const DNS_RESOLVER_PORT: u16 = crate::dns_resolver::DEFAULT_BIND_PORT;

/// Where the local CA root cert is installed on Debian/Ubuntu so
/// `update-ca-certificates` picks it up. Per `man
/// update-ca-certificates`: any `.crt` file in this directory is
/// hashed into `/etc/ssl/certs/ca-certificates.crt` on next
/// `update-ca-certificates` run.
pub const DEBIAN_CA_TRUST_DIR: &str = "/usr/local/share/ca-certificates";

/// Filename for our CA root in the trust dir. Stable so uninstall
/// can `rm` it deterministically.
pub const CA_ROOT_FILENAME: &str = "p2claw-local-ca.crt";

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("Linux system-scope install requires root; re-run with `sudo`")]
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
    #[error(
        "this Linux distribution doesn't appear to use Debian-style \
         `update-ca-certificates` ({detail}). Install only supports \
         Debian/Ubuntu today; Fedora/RHEL operators: copy `{ca_path}` into \
         `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust` manually."
    )]
    UnsupportedDistro { detail: String, ca_path: String },
}

/// Options for [`install_system`].
pub struct InstallSystemOpts {
    pub bin_path: Option<PathBuf>,
    pub parent_domain: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub no_start: bool,
    pub dry_run: bool,
}

/// Options for [`uninstall_system`]. Symmetric subset.
pub struct UninstallSystemOpts {
    pub parent_domain: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub dry_run: bool,
}

pub fn install_system(opts: InstallSystemOpts) -> Result<(), InstallError> {
    if !is_root() && !opts.dry_run {
        return Err(InstallError::NotRoot);
    }

    // 1. Resolve the binary path the unit should run.
    let bin = resolve_bin(opts.bin_path.clone())?;
    if !bin.exists() {
        return Err(InstallError::BinNotFound {
            bin: "p2claw",
            path: bin.display().to_string(),
        });
    }

    // 2. Resolve data_dir + parent_domain.
    let data_dir = opts.data_dir.clone().unwrap_or_else(default_linux_data_dir);
    let parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 3. Pre-flight: 443 isn't already bound elsewhere.
    if let Err(detail) = check_443_free() {
        return Err(InstallError::PortConflict { detail });
    }

    // 4. Pre-flight: `update-ca-certificates` available. If not,
    //    surface the Fedora-style alternative cleanly.
    if !opts.dry_run {
        check_debian_ca_tooling()?;
    }

    // 5. Mint the local CA root if it's missing on disk.
    let ca_cert_path = data_dir.join("local_ca.crt");
    if !ca_cert_path.exists() {
        info!(
            data_dir = %data_dir.display(),
            "linux_install: minting local CA root (load_or_generate)"
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

    // 6. Install CA root into the system trust store.
    let installed_ca_path = PathBuf::from(DEBIAN_CA_TRUST_DIR).join(CA_ROOT_FILENAME);
    if !opts.dry_run {
        std::fs::create_dir_all(DEBIAN_CA_TRUST_DIR).map_err(|e| InstallError::Io {
            path: DEBIAN_CA_TRUST_DIR.to_string(),
            source: e,
        })?;
        std::fs::copy(&ca_cert_path, &installed_ca_path).map_err(|e| InstallError::Io {
            path: installed_ca_path.display().to_string(),
            source: e,
        })?;
        run_tool("update-ca-certificates", "rebuild trust bundle", &[])?;
    }
    print_action(
        opts.dry_run,
        &format!(
            "installed CA root at {} + ran update-ca-certificates",
            installed_ca_path.display()
        ),
    );

    // 7. Write the systemd-resolved drop-in for DNS routing.
    let resolved_dropin_path = resolved_dropin_path();
    let resolved_body = render_resolved_dropin(&parent_domain, DNS_RESOLVER_PORT);
    write_atomic(&resolved_dropin_path, &resolved_body, 0o644, opts.dry_run)?;
    print_action(
        opts.dry_run,
        &format!("wrote {}", resolved_dropin_path.display()),
    );

    // 8. Write the system-scope systemd unit.
    //
    // Capture the install-time environment for the small set of
    // P2CLAW_* env vars the daemon needs but that systemd's
    // service environment WON'T inherit by default. Without this,
    // an agent invoked via `sudo p2claw service install --system`
    // (where the operator's shell has e.g. P2CLAW_COORD_URL set)
    // would lose those values when systemd later starts the unit
    // — the daemon would fall back to clap defaults
    // (`coord_domain=coord.p2claw.com`, `coord_url=None` →
    // derived `https://coord.p2claw.com`). For the e2e harness
    // that means the agent's peer_dialer dials production coord;
    // for self-hosted operators it's the same problem with
    // whatever URL their coord lives at. Capturing here keeps
    // the agent's daemon-time view aligned with the install-time
    // operator intent.
    // Allow-list of P2CLAW_* env vars whose install-time value
    // should land in the daemon's runtime env. Add new entries
    // here when a future agent flag needs the same install-time
    // capture. (Generic capture-all-P2CLAW_* would be
    // over-permissive: e.g. P2CLAW_AGENT_DATA_DIR is already
    // emitted explicitly with a curated path; capturing it from
    // env would duplicate.)
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
        // Operator-set DNS-port override propagates from
        // install shell into the systemd unit. Linux default is
        // 5354 (mDNS-conflict-free); operators only set this if
        // they explicitly want 53 (which then needs
        // CAP_NET_BIND_SERVICE — already in the rendered unit) or
        // a different non-default port.
        ("P2CLAW_DNS_PORT", std::env::var("P2CLAW_DNS_PORT").ok()),
    ];
    let extra_env: Vec<(&str, &str)> = captured
        .iter()
        .filter_map(|(k, v)| v.as_deref().map(|s| (*k, s)))
        .collect();
    let unit_path = systemd_unit_path();
    let unit_body = render_systemd_unit(&bin, &data_dir, &extra_env);
    write_atomic(&unit_path, &unit_body, 0o644, opts.dry_run)?;
    print_action(opts.dry_run, &format!("wrote {}", unit_path.display()));
    if !extra_env.is_empty() {
        let keys = extra_env
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(", ");
        print_action(
            opts.dry_run,
            &format!("(captured install-time env into unit: {keys})"),
        );
    }

    // 9. systemctl daemon-reload + restart resolver + start unit.
    if !opts.dry_run {
        run_tool("systemctl", "daemon-reload", &["daemon-reload"])?;
        // systemd-resolved restart picks up the new dropin.
        // Best-effort: on a host where systemd-resolved isn't
        // running, log a warn but continue (operator may use
        // NetworkManager-managed DNS or another resolver).
        if let Err(e) = run_tool(
            "systemctl",
            "restart systemd-resolved",
            &["restart", "systemd-resolved"],
        ) {
            warn!(
                error = %e,
                "linux_install: systemd-resolved restart failed; \
                 DNS routing may not be active. Operator may need to \
                 configure DNS manually for *.{parent_domain} → 127.0.0.1:{DNS_RESOLVER_PORT}"
            );
        }
    }

    if opts.no_start {
        print_action(
            opts.dry_run,
            &format!(
                "(--no-start) skipped `enable --now`. Enable later with:\n  \
                 sudo systemctl enable --now {SYSTEMD_UNIT_FILENAME}"
            ),
        );
    } else if !opts.dry_run {
        run_tool(
            "systemctl",
            "enable --now",
            &["enable", "--now", SYSTEMD_UNIT_FILENAME],
        )?;
        print_action(
            opts.dry_run,
            &format!("enabled and started {SYSTEMD_UNIT_FILENAME}"),
        );
    }

    print_action(opts.dry_run, "linux_install: done");
    Ok(())
}

pub fn uninstall_system(opts: UninstallSystemOpts) -> Result<(), InstallError> {
    if !is_root() && !opts.dry_run {
        return Err(InstallError::NotRoot);
    }

    let data_dir = opts.data_dir.clone().unwrap_or_else(default_linux_data_dir);
    let _parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 1. Stop + disable the unit (best-effort; non-fatal if absent).
    if !opts.dry_run {
        if let Err(e) = run_tool(
            "systemctl",
            "disable --now",
            &["disable", "--now", SYSTEMD_UNIT_FILENAME],
        ) {
            warn!(error = %e, "linux_install: systemctl disable --now (uninstall) failed");
        }
    }

    // 2. Remove the unit file.
    let unit_path = systemd_unit_path();
    if unit_path.exists() {
        if !opts.dry_run {
            std::fs::remove_file(&unit_path).map_err(|e| InstallError::Io {
                path: unit_path.display().to_string(),
                source: e,
            })?;
        }
        print_action(opts.dry_run, &format!("removed {}", unit_path.display()));
    } else {
        print_action(
            opts.dry_run,
            &format!("(no unit at {})", unit_path.display()),
        );
    }

    // 3. Remove the systemd-resolved drop-in.
    let resolved_dropin_path = resolved_dropin_path();
    if resolved_dropin_path.exists() {
        if !opts.dry_run {
            std::fs::remove_file(&resolved_dropin_path).map_err(|e| InstallError::Io {
                path: resolved_dropin_path.display().to_string(),
                source: e,
            })?;
        }
        print_action(
            opts.dry_run,
            &format!("removed {}", resolved_dropin_path.display()),
        );
    } else {
        print_action(
            opts.dry_run,
            &format!("(no resolved dropin at {})", resolved_dropin_path.display()),
        );
    }

    // 4. Remove the CA root from the trust store.
    let installed_ca_path = PathBuf::from(DEBIAN_CA_TRUST_DIR).join(CA_ROOT_FILENAME);
    if installed_ca_path.exists() {
        if !opts.dry_run {
            std::fs::remove_file(&installed_ca_path).map_err(|e| InstallError::Io {
                path: installed_ca_path.display().to_string(),
                source: e,
            })?;
            // Best-effort rebuild of the trust bundle.
            let _ = run_tool(
                "update-ca-certificates",
                "rebuild trust bundle",
                &["--fresh"],
            );
        }
        print_action(
            opts.dry_run,
            &format!(
                "removed {} + ran update-ca-certificates --fresh",
                installed_ca_path.display()
            ),
        );
    } else {
        print_action(
            opts.dry_run,
            &format!("(no CA cert at {})", installed_ca_path.display()),
        );
    }

    // 5. Reload systemd + restart resolver so changes take effect.
    if !opts.dry_run {
        let _ = run_tool("systemctl", "daemon-reload", &["daemon-reload"]);
        let _ = run_tool(
            "systemctl",
            "restart systemd-resolved (uninstall)",
            &["restart", "systemd-resolved"],
        );
    }

    print_action(opts.dry_run, "linux_install: uninstall done");
    Ok(())
}

/// Pre-flight 443 check; same body as macOS. Belt-and-suspenders
/// on `127.0.0.1` AND `0.0.0.0` since loopback bind doesn't
/// always conflict with wildcard bind on Linux either (depends on
/// `SO_REUSEADDR` posture of the conflicting service).
pub fn check_443_free() -> Result<(), String> {
    match TcpListener::bind("127.0.0.1:443") {
        Ok(l) => drop(l),
        Err(e) => {
            let detail = match Command::new("ss")
                .args(["-ltnp", "( sport = :443 )"])
                .output()
            {
                Ok(out) if out.status.success() => format!(
                    "127.0.0.1:443 bind failed ({e}); current owner per `ss -ltnp`:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                ),
                _ => format!(
                    "127.0.0.1:443 bind failed ({e}); install `ss` (iproute2) for owner info"
                ),
            };
            return Err(detail);
        }
    }
    match TcpListener::bind("0.0.0.0:443") {
        Ok(l) => drop(l),
        Err(e) => return Err(format!("0.0.0.0:443 bind failed ({e})")),
    }
    Ok(())
}

/// Render the systemd-resolved drop-in. Per `man resolved.conf`:
/// `[Resolve] DNS=` lists the upstream DNS servers; `Domains=`
/// with a `~` prefix tells the resolver "for queries matching
/// these domains, use the listed DNS servers exclusively
/// (don't fall back)." Combining both routes `*.<parent_domain>`
/// queries to our local resolver while leaving everything else
/// on the system's normal DNS path.
pub fn render_resolved_dropin(parent_domain: &str, loopback_port: u16) -> String {
    format!(
        "# Generated by `p2claw service install --system`. Reverses on uninstall.\n\
         # Routes *.<parent_domain> queries to the local p2claw DNS resolver\n\
         # (`crates/agent/src/dns_resolver.rs`) which synthesizes A records\n\
         # at 127.0.0.1 + chains everything else upstream. See `man resolved.conf`.\n\
         [Resolve]\n\
         DNS=127.0.0.1:{loopback_port}\n\
         Domains=~{parent_domain}\n",
    )
}

/// Render the system-scope systemd unit. Differences from the
/// user-scope unit (`service.rs::render_unit`):
/// - `[Install] WantedBy=multi-user.target` (not `default.target`,
///   which is user-session-scoped).
/// - `User=` + `Group=` not set (defaults to root). Future work
///   will flip this to a dedicated `_p2claw` user once the
///   data_dir layout supports it.
/// - `AmbientCapabilities=CAP_NET_BIND_SERVICE` so the agent can
///   bind 443 without needing root for the whole process; combined
///   with `CapabilityBoundingSet=` to drop everything else, this
///   is "just enough privilege to bind low ports."
/// - `Environment=P2CLAW_AGENT_DATA_DIR=<data_dir>` so the agent
///   reads its identity / state from the system path rather than
///   the user's `~/.local/share/p2claw`.
/// - `[Service] StateDirectory=p2claw` creates `/var/lib/p2claw`
///   owned by the unit's user (root for now), `0700` mode.
pub fn render_systemd_unit(bin_path: &Path, data_dir: &Path, extra_env: &[(&str, &str)]) -> String {
    // Render any operator-supplied env captures (currently
    // `P2CLAW_COORD_URL` / `P2CLAW_COORD_DOMAIN` / etc) as one
    // `Environment=KEY=VALUE` line each. systemd accepts any number
    // of these directives.
    let extra_env_lines = extra_env
        .iter()
        .map(|(k, v)| format!("Environment={k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let extra_env_block = if extra_env_lines.is_empty() {
        String::new()
    } else {
        format!("\n{extra_env_lines}")
    };
    format!(
        "\
[Unit]
Description=p2claw agent (system scope)
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} run
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
# CAP_NET_BIND_SERVICE lets the SNI listener bind 443 without
# the agent process running as root for its lifetime. Combined
# with the bounding set, the agent has no other capabilities —
# narrower attack surface than a plain root daemon.
# The priv-drop dance layers on top.
#
# CAP_SETGID + CAP_SETUID are required for the setgid+setuid
# drop to a dedicated user post-bind. Without these in the
# CapabilityBoundingSet, the kernel returns EPERM on the
# setgid() syscall even from EUID=0 — the bounding set is the
# upper bound on what the process can ever hold, regardless of
# EUID (the agent fails to start with `setgid(65534) failed
# (EUID is 0): EPERM`).
#
# These caps land in the bounding set (so setuid/setgid CAN be
# called) but NOT in AmbientCapabilities (which would let them
# survive the drop). After priv_drop::drop_to runs, the kernel
# clears the effective + permitted cap sets — the dropped agent
# holds zero capabilities, including no path back to setuid
# (matches priv_drop defense-in-depth setuid(0) MUST fail
# check). Idiomatic systemd bind-privileged-then-drop capset.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
# `RuntimeDirectory=p2claw` materialises `/run/p2claw` at service
# start (mode 0755, owned by the unit's User=) and tears it down
# at stop. Combined with `config::runtime_dir()`'s root-prefers-
# /run/p2claw branch, the agent's local-API socket lands at
# `/run/p2claw/agent.sock` — which is visible to CLI tools
# (`p2claw expose` etc.) DESPITE this unit's `PrivateTmp=true`,
# because /run is mounted from the host. Previously the socket lived
# under /tmp/p2claw-0 and PrivateTmp made it invisible to the
# bootstrap script; the canonical systemd RuntimeDirectory pattern
# fixes that without dropping any hardening.
RuntimeDirectory=p2claw
RuntimeDirectoryMode=0755
Environment=P2CLAW_AGENT_DATA_DIR={data_dir}{extra_env_block}

[Install]
WantedBy=multi-user.target
",
        bin = bin_path.display(),
        data_dir = data_dir.display(),
        extra_env_block = extra_env_block,
    )
}

// ---------- helpers ----------

fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

fn systemd_unit_path() -> PathBuf {
    PathBuf::from(SYSTEMD_SYSTEM_DIR).join(SYSTEMD_UNIT_FILENAME)
}

fn resolved_dropin_path() -> PathBuf {
    PathBuf::from(RESOLVED_DROPIN_DIR).join(RESOLVED_DROPIN_FILENAME)
}

/// Fixed system data dir for system-scope installs. Distinct from
/// the per-user `~/.local/share/p2claw` so a system-scope agent
/// never accidentally inherits a user-scope's identity / state.
fn default_linux_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/p2claw")
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

/// Detect the Debian/Ubuntu trust-store tooling. Currently a
/// shallow "is `update-ca-certificates` on PATH?" check —
/// distros that don't ship it (Fedora/RHEL/Alpine) get an
/// explicit error pointing at their own command + the cert
/// path. Future work: parse `/etc/os-release` and dispatch
/// per-distro.
fn check_debian_ca_tooling() -> Result<(), InstallError> {
    match Command::new("update-ca-certificates")
        .arg("--help")
        .output()
    {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(InstallError::UnsupportedDistro {
            detail: format!("`update-ca-certificates --help` exited {}", out.status),
            ca_path: PathBuf::from(DEBIAN_CA_TRUST_DIR)
                .join(CA_ROOT_FILENAME)
                .display()
                .to_string(),
        }),
        Err(e) => Err(InstallError::UnsupportedDistro {
            detail: format!("could not exec `update-ca-certificates`: {e}"),
            ca_path: PathBuf::from(DEBIAN_CA_TRUST_DIR)
                .join(CA_ROOT_FILENAME)
                .display()
                .to_string(),
        }),
    }
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
    fn resolved_dropin_render_includes_parent_domain_and_port() {
        // Using DNS_RESOLVER_PORT (= dns_resolver::DEFAULT_BIND_PORT)
        // so this test follows the source-of-truth port automatically.
        // The pre-fix version hard-coded 5454, which masked the
        // installer-vs-resolver port mismatch (real bug-of-record);
        // by sourcing from the resolver's own constant the test
        // would now FAIL if the divergence reappeared.
        let body = render_resolved_dropin("p2claw.com", DNS_RESOLVER_PORT);
        assert!(body.contains("[Resolve]"));
        assert!(
            body.contains(&format!("DNS=127.0.0.1:{DNS_RESOLVER_PORT}")),
            "drop-in must point at the same port the resolver binds"
        );
        // Pin the actual numeric value too — if dns_resolver
        // ever rebases its DEFAULT_BIND_PORT, this assertion's
        // failure tells the next reader to check both ends are
        // intentionally aligned (e.g. mDNS conflict avoidance).
        assert_eq!(
            DNS_RESOLVER_PORT, 5354,
            "expected dns_resolver::DEFAULT_BIND_PORT to be 5354 \
             (avoids well-known 5353 mDNS); if you're changing it, \
             also update the install integration tests + macOS install."
        );
        // `~p2claw.com` is the systemd-resolved syntax for
        // "route this domain (and subs) exclusively to the listed
        // DNS server" — without the `~`, systemd-resolved would
        // still fall back to the system-default DNS server,
        // which would shadow our synth A records.
        assert!(body.contains("Domains=~p2claw.com"));
        assert!(body.contains("Reverses on uninstall"));
    }

    #[test]
    fn systemd_unit_render_includes_capability_and_data_dir() {
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let data = PathBuf::from("/var/lib/p2claw");
        let unit = render_systemd_unit(&bin, &data, &[]);
        assert!(unit.contains("ExecStart=/opt/p2claw/p2claw run"));
        // CAP_NET_BIND_SERVICE is the load-bearing privilege —
        // without it the SNI listener can't bind 443. Stays in
        // AmbientCapabilities so it survives the priv-drop (the
        // dropped agent doesn't need it post-bind, but listing it
        // ambient at start is what gives a non-root EUID the cap
        // in the first place — needed for the dev path where the
        // unit could conceivably run under a non-root User=).
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        // CapabilityBoundingSet must include CAP_SETGID +
        // CAP_SETUID alongside CAP_NET_BIND_SERVICE so the
        // priv-drop dance can call setgid/setuid from EUID=0
        // (without these, the kernel returns EPERM on setgid even
        // at EUID=0 because the bounding set is the upper bound on
        // what the process can ever hold). Pin all three so a
        // future edit can't drop one silently.
        assert!(
            unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID"),
            "expected the union capset (NET_BIND_SERVICE + SETGID + SETUID); got:\n{unit}"
        );
        // NoNewPrivileges + ProtectSystem + PrivateTmp narrow the
        // process's filesystem reach. systemd-hardening default
        // for daemons that don't need to write outside their
        // StateDirectory.
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=full"));
        assert!(unit.contains("PrivateTmp=true"));
        // Data dir is wired through the env var the agent reads
        // (`P2CLAW_AGENT_DATA_DIR` per `config.rs`), so the
        // system-scope install + user-scope install can coexist
        // on the same machine without sharing identity files.
        assert!(unit.contains("P2CLAW_AGENT_DATA_DIR=/var/lib/p2claw"));
        // System-scope install targets `multi-user.target`
        // (boot-time on a real box), not `default.target` (user-
        // session bound). Mismatched [Install] section here would
        // mean the unit doesn't auto-start at boot.
        assert!(unit.contains("WantedBy=multi-user.target"));
        // Inherits the FD-limit bump since a system-scope
        // install hits the same prod traffic as the user-scope.
        assert!(unit.contains("LimitNOFILE=65536"));
        // `After=systemd-resolved.service` so the resolver-dropin
        // change is picked up before the agent starts trying to
        // serve.
        assert!(unit.contains("systemd-resolved.service"));
        // A real bug-of-record: PrivateTmp=true hid the
        // /tmp/p2claw-0/agent.sock from CLI tools that didn't
        // share the unit's tmp namespace. The fix is the
        // canonical systemd `RuntimeDirectory=p2claw` pattern,
        // which materialises /run/p2claw at start (visible
        // outside the tmp namespace because /run isn't part of
        // PrivateTmp) and tears it down at stop. The
        // `config::runtime_dir()` Linux branch prefers
        // /run/p2claw when running as root + the dir exists, so
        // the agent's local-API socket lands there + CLI tools
        // resolve the same path. If you remove this directive,
        // also remove the root-prefers-/run/p2claw branch in
        // config.rs — they're a coupled pair.
        assert!(
            unit.contains("RuntimeDirectory=p2claw"),
            "system-scope unit must declare RuntimeDirectory=p2claw \
             for the local-API socket to be visible outside the \
             unit's PrivateTmp namespace"
        );
        assert!(unit.contains("RuntimeDirectoryMode=0755"));
    }

    #[test]
    fn systemd_unit_render_emits_extra_env_lines() {
        // A real bug-of-record: systemd doesn't
        // inherit the install-time shell's env, so any `P2CLAW_*`
        // env var the operator had set (e.g. P2CLAW_COORD_URL
        // pointing at a self-hosted coord) was lost when the
        // daemon later ran under the unit. install_system now
        // captures those at install-time and bakes them into the
        // unit via this `extra_env` parameter. Pin the
        // serialization shape so a future template edit doesn't
        // accidentally drop the lines.
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let data = PathBuf::from("/var/lib/p2claw");
        let extra = [
            ("P2CLAW_COORD_URL", "http://coord:8081"),
            ("P2CLAW_COORD_DOMAIN", "coord.p2claw.test"),
        ];
        let unit = render_systemd_unit(&bin, &data, &extra);
        // Each entry becomes one Environment= line. Order matches
        // the slice — easier to reason about + keeps the output
        // deterministic for diff-based ops review.
        assert!(
            unit.contains("Environment=P2CLAW_COORD_URL=http://coord:8081"),
            "missing captured P2CLAW_COORD_URL line; got:\n{unit}"
        );
        assert!(
            unit.contains("Environment=P2CLAW_COORD_DOMAIN=coord.p2claw.test"),
            "missing captured P2CLAW_COORD_DOMAIN line"
        );
        // Existing always-emitted env line still present alongside.
        assert!(
            unit.contains("Environment=P2CLAW_AGENT_DATA_DIR=/var/lib/p2claw"),
            "always-emitted data-dir line missing"
        );
    }

    #[test]
    fn systemd_unit_render_with_no_extra_env_omits_extra_block() {
        // When `extra_env` is empty (no operator env captured at
        // install time), the unit should NOT have a trailing blank
        // Environment line that would parse as malformed. Pin the
        // empty-extra path emits exactly the always-emitted
        // data-dir line + nothing extra.
        let bin = PathBuf::from("/opt/p2claw/p2claw");
        let data = PathBuf::from("/var/lib/p2claw");
        let unit = render_systemd_unit(&bin, &data, &[]);
        // Exactly one Environment= line in the rendered unit.
        let env_count = unit.matches("Environment=").count();
        assert_eq!(
            env_count, 1,
            "expected exactly 1 Environment= line, got {env_count}:\n{unit}"
        );
    }

    #[test]
    fn systemd_unit_path_is_system_scope() {
        let p = systemd_unit_path();
        assert_eq!(p, PathBuf::from("/etc/systemd/system/p2claw-agent.service"));
    }

    #[test]
    fn resolved_dropin_path_is_under_dropin_dir() {
        let p = resolved_dropin_path();
        assert_eq!(p, PathBuf::from("/etc/systemd/resolved.conf.d/p2claw.conf"));
    }

    #[test]
    fn read_parent_domain_from_state_extracts_field() {
        let dir = tempfile::tempdir().unwrap();
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

    #[test]
    fn default_linux_data_dir_is_var_lib_p2claw() {
        // The fixed system data dir is distinct from the per-user
        // `~/.local/share/p2claw` so a system-scope agent never
        // accidentally inherits a user-scope's identity. If you
        // change this constant, also update the `[Service]
        // Environment=` line in `render_systemd_unit` so the
        // agent reads from the same path the install writes to.
        assert_eq!(default_linux_data_dir(), PathBuf::from("/var/lib/p2claw"));
    }
}
